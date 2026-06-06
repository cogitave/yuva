# TABOS Vizyon Dökümanı

**Türkiye's Agent Based Operating System**

> Durum: v1.0 (planlama fazı) · Dayanak: [RESEARCH-REPORT](RESEARCH-REPORT.md)
> İlgili: [ARCHITECTURE](ARCHITECTURE.md) · [MEMORY-SPEC](MEMORY-SPEC.md) · [AGENTS-SPEC](AGENTS-SPEC.md) · [SELF-IMPROVEMENT-SPEC](SELF-IMPROVEMENT-SPEC.md) · [OPEN-QUESTIONS](OPEN-QUESTIONS.md)

---

## 1. Tek Cümlede TABOS

**TABOS, AI agent'ın ve bilgisayarının tek bir kernel nesnesi olduğu; hafızanın, kendini geliştirmenin ve çoklu-agent yaşamının işletim sistemi garantisi olarak sunulduğu, sıfırdan tasarlanmış bir işletim sistemidir.**

Linux'un insan operatör için olduğu neyse, TABOS agent için odur — ama Linux'un 35 yıllık insan-masaüstü mirasını (tty'ler, çok-kullanıcılı uid modeli, X11, insan-okunur olmayan binary ABI'ler, agent'ın hiç çağırmayacağı yüzlerce syscall) hiç taşımadan.

## 2. Neden Var? — Boşluk Analizi

Araştırmanın en keskin bulgusu ([RESEARCH-REPORT §5](RESEARCH-REPORT.md#5-mevcut-sistemler-ve-greenfield-gerekçesi)): bugünkü ekosistemde agent'ın "zihni" ile "elleri" ayrı sistemlerde yaşıyor ve hiçbir sistem ikisini birden sahiplenmiyor:

| Sistem | Sahiplendiği parça | Sahiplenemediği |
|---|---|---|
| **E2B** | Bilgisayar (microVM, FS+RAM snapshot) | Agent'ın zihni — context, memory, LLM döngüsü host uygulamasında |
| **Letta** | Zihin (.af: memory blocks, mesaj geçmişi, tool tanımları) | Execution sandbox durumu; eşzamanlılık (last-write-wins) |
| **AIOS** | Scheduling (LLM syscalls, 2.1× throughput) | İzolasyon (Python daemon, hashmap ACL); kalıcı per-user kernel "ongoing" |

**Hiçbiri `{context window + memory tier'ları + in-flight inference durumu + sandbox process'leri + dosya sistemi}` bütününü tek atomik birim olarak suspend/resume/migrate/fork edemiyor.** TABOS'un varlık nedeni bu join'i kernel düzeyinde sahiplenmek: *torn-state yok* — beyin ile eller arasında yarım kalmış checkpoint olmaz; capability beyinden ele kernel'dan çıkmadan akar; tek kaynak hesabı (token + CPU + RAM + disk + dolar).

## 3. Tasarım Felsefesi — Beş İlke

### İlke 1: Her alt sistem "agent'a ne kazandırıyor?" sorusuyla yaşar
Kullanıcının kurucu kısıtı. Bir alt sistem agent'ın yapabileceklerinin potansiyelini büyütmüyorsa TABOS'ta yeri yoktur. Mimari karşılığı library-OS modülerliğidir (Unikraft: yalnızca gereken bileşenler derlenir, ~1 MB imaj [arXiv:2104.12721]). İnsan-masaüstü mirası sıfır: terminal emülasyonu yok, çok-kullanıcılı oturum yok, GUI altyapısı yok. İnsan, TABOS'a *operatör* olarak değil **consent-verici ve gözlemci** olarak dokunur (elicitation kanalı, audit ağaçları).

### İlke 2: Memory bir özellik değil, kernel garantisidir
Bugün memory her framework'ün yeniden icat ettiği bir kütüphane. TABOS'ta **default, kalıcı, katmanlı memory her agent'a doğuştan verilir** — dosya sistemi nasıl "opsiyonel" değilse. KeyKOS'un orthogonal persistence'ı şablon: agent'ın bütün durumu elektrik kesintisini "saatin sıçraması" gibi yaşar; **hibernate default'tur, terminate istisnadır.** Detay: [MEMORY-SPEC](MEMORY-SPEC.md).

### İlke 3: Ambient authority yoktur — yetki her zaman görünür ve devredilirken zayıflar
Agent'lar Shapiro'nun "programs, not people" eleştirisinin ([EROS essay](RESEARCH-REPORT.md#35-i̇zolasyon-temelleri-plan-9-keykoseros-capsicum-zirconfuchsia-redox-wasm-gvisor)) ta kendisidir: prompt-injection'a açık, üçüncü-parti kodla beslenen, birbirine güvenmeyen aktörler. TABOS'ta POSIX uid modeli hiç var olmaz; her tool çağrısı, her memory erişimi, her model invokasyonu **explicit capability** üzerinden (Zircon handle+rights modeli; attenuation-only duplicate; tek bootstrap handle ile doğum). Bunun bonusu: karşılıklı-şüpheli işbirliği — senin gizli verinde benim tescilli agent'ım, iki taraf da sızdıramadan.

### İlke 4: Token, context ve inference schedule edilebilir kaynaklardır
CPU-saniyesi ve RAM-byte'ı nasıl kaynaksa, ITPM/OTPM kotası, KV-cache bloğu, context window'u ve dolar da kaynaktır. seL4 MCS'in budget+period scheduling-context capability'leri compute için üretimde kanıtlandı (formal verification'ı hâlâ sürüyor); TABOS aynı modeli token akışlarına uygular. Kernel'da tek nötr **context scheduler**, altında iki driver ailesi: lokal (HBM, GPU-saniye) ve remote (dolar, kota). Asimetrik koz: kalıcı durum token *metni* olduğundan (KV yeniden hesaplanabilir cache'tir [vLLM]), agent migrasyonu GB değil KB taşır.

### İlke 5: Kendini geliştirme OS servisidir — ama ölçen, ölçülenden ayrıdır
Reflection, skill birikimi, deneyim damıtma her agent'a default-on sunulur (weight-free, dolayısıyla LLM-agnostik [Reflexion]). Ama Darwin Gödel Machine'in dersi kuraldır: **frozen kernel / evolving userspace** — evaluator'lar, güvenlik dedektörleri ve evrim makinesi agent'ın okuyamayacağı/yazamayacağı katmandadır (görünür metrik Goodhart'lanır; DGM'de ajan dedektörü fiilen bypass etti). Öncelik hiyerarşisi kernel'da kodludur: **Endure > Excel > Evolve** [arXiv:2508.07407]. Detay: [SELF-IMPROVEMENT-SPEC](SELF-IMPROVEMENT-SPEC.md).

## 4. TABOS'un Birinci Sınıf Vatandaşları

1. **Agent process** — `{context + memory + inference + sandbox + FS}` tek nesne; atomik checkpoint/fork/migrate ([AGENTS-SPEC](AGENTS-SPEC.md))
2. **Memory record / tier** — bi-temporal damgalı, provenance'lı, kotali ([MEMORY-SPEC](MEMORY-SPEC.md))
3. **Capability/handle** — haklar maskesiyle, yalnızca zayıflayarak çoğalan yetki
4. **Task** — 9-durumlu, durable, insan/credential-bloklu durumları olan iş birimi (A2A modeli)
5. **Token budget** — budget+period'lu, hiyerarşik, devredilebilir bütçe
6. **Skill** — kod + açıklama + embedding + utility skoru; verification-before-commit ile kabul
7. **Session** — bir veya N agent'ın paylaşımlı blackboard ve event stream'leriyle ortak yaşam alanı

## 5. Kimlik: İsim ve Dil

- **TABOS** = *Türkiye's Agent Based Operating System* — **kod adı (working title)**, nihai marka değil; değişebilir, rezervasyon bilinçli yapılmadı. 31 adayın (24+7; 23'ü tam vetlendi) iki turlu vetlemesinden sonra kod adı olarak seçildi; npm/PyPI/crates boş, AI/agent/OS alanında aktif çakışma yok ([RESEARCH-REPORT §9](RESEARCH-REPORT.md#9-i̇simlendirme-süreci-ve-tabos-kararı)).
- Kernel sembol öneki (kod adına bağlı placeholder): **`tb_`** (syscall'lar), **`TB_`** (sabitler). CLI: `tabos` / `tb`. Hiçbir spec isme semantik bağımlılık taşımaz — isim değişirse mekanik find-replace yeter.
- Alt sistem adlandırması için rezerv kavram havuzu (vetleme sırasında "konsept olarak güzel ama marka olarak dolu" çıkanlar iç isim olarak serbest): `daemon`→agent supervisor, `synapse`→IPC kanalları, `engram`→memory record'un iç adı, `hexis`→skill nesnesinin iç adı.
- Proje dili: dökümantasyon Türkçe (teknik terimler İngilizce); kod/kimlikler İngilizce (uluslararası katkıya açık).

## 6. Kapsam Dışı (bilinçli)

- **Genel amaçlı insan masaüstü/sunucu OS'u olmak** — Linux'la rekabet yok; agent-dışı işyükleri hedef değil.
- **Kendi LLM'ini eğitmek/barındırmak zorunda olmak** — inference her zaman driver arkasında (remote API veya lokal engine); TABOS model değil, modelin *evi*.
- **v1'de kendi donanım driver evrenini yazmak** — TABOS bir hypervisor/VMM üstünde (KVM/Firecracker-sınıfı) guest olarak boot eder; çıplak donanım sonraki faz ([OPEN-QUESTIONS](OPEN-QUESTIONS.md)).
- **Tek protokole evlilik** — MCP/A2A/ACP/ANP userspace bridge'lerdir; kernel ABI'si nötr kalır.

## 7. Başarı Kriterleri (planlama fazı çıkış çubukları)

| # | Kriter | Ölçü |
|---|---|---|
| 1 | Agent spawn soğuk başlangıcı | E2B çıtası <200 ms'nin altı; unikernel hattıyla hedef **<50 ms** |
| 2 | Atomik checkpoint | Zihin+bilgisayar tek imaj; resume sonrası torn-state sıfır |
| 3 | Memory default'u | Hiçbir framework kodu yazmadan kalıcı recall; p95 retrieval <200 ms (Mem0 çıtası) |
| 4 | Kota verimliliği | Cache-aware yerleşimle aynı ITPM'de ≥3× efektif iş (Anthropic cache-exempt aritmetiği) |
| 5 | Self-improvement geri ödemesi | Sleep-time compute sınıfında ≥2× test-time compute düşüşü (Letta ~5× çıtası) |
| 6 | Güvenlik | Ambient authority sıfır; her yetki spawn anında numaralandırılabilir; evaluator'lar agent'tan okunamaz |

## 8. Yol Haritası Görünümü (taslak)

1. **Faz 0 — bu klasör:** Döküman seti + açık soruların kapatılması (spec donması).
2. **Faz 1 — çekirdek prototip:** Handle/capability katmanı + agent process nesnesi + memory T0-T2 tier'ları; host: Linux üstü user-mode prototip (hızlı iterasyon için), hedef ABI'yi koruyarak.
3. **Faz 2 — gerçek izolasyon:** Firecracker-sınıfı microVM'de TABOS unikernel guest; WASM nanoprocess tool runtime'ı; context scheduler v1 (remote lease driver'ı önce).
4. **Faz 3 — çoklu-agent + self-improvement:** Session/blackboard, A2A bridge, sleep-time sınıfı, skill compiler.
5. **Faz 4 — ekosistem:** Agent imaj formatı + paket/agent hub'ı (Cerebrum dersleri), .af import uyumluluğu.

> Fazlar [OPEN-QUESTIONS](OPEN-QUESTIONS.md)'taki kernel-vs-userspace kararları kapanmadan taahhüt değildir.
