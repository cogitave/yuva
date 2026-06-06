# TABOS Agent Spesifikasyonu (Tek/Çoklu Agent, Scheduling, IPC)

> Durum: v1.0 taslak — **[KARAR] / [ÖNERİ] / [AÇIK]** işaretli.
> Dayanak: [RESEARCH-REPORT §5-6-8](RESEARCH-REPORT.md) · İlgili: [ARCHITECTURE](ARCHITECTURE.md) · [MEMORY-SPEC](MEMORY-SPEC.md) · [SELF-IMPROVEMENT-SPEC](SELF-IMPROVEMENT-SPEC.md)

---

## 1. Agent Process Nesnesi **[KARAR]**

TABOS'un schedule edilebilir, checkpoint'lenebilir, migrate edilebilir birimi:

```
AgentProcess = {
  manifest,            # imzalı; prefix→handle tablosu; yetenek deklarasyonları
  context,             # T0 register seti + token-metni kanonik durumu (KV = cache)
  memory,              # tier handle'ları (MEMORY-SPEC; private ev otomatik)
  inference,           # açık ModelSession'lar, in-flight DAG future'ları, lease'ler
  sandbox,             # WASM nanoprocess'ler + (varsa) alt-microVM; FS delta
  tasks,               # sahip olunan/üstlenilen Task nesneleri (9-durum)
  budget,              # token/dolar/CPU bütçe handle'ları (hiyerarşik)
  identity,            # principal + türetilmiş task-scoped alt-kimlikler (ANP çok-DID)
  handles              # yukarıdakilerin tamamının tek tablosu — yetki = bu tablo
}
```

**Atomik bütünlük garantisi**: checkpoint/fork/migrate bu yapının *tamamını* tek işlemde alır — beyin/el arasında torn-state olmaz (E2B/Letta/AIOS boşluğunun kapanışı, [VISION §2](VISION.md)).

## 2. Yaşam Döngüsü **[ÖNERİ]**

A2A 9-durum makinesi scheduler-native alınır, iki TABOS eklentisiyle:

```
SUBMITTED → WORKING ⇄ {INPUT_REQUIRED, AUTH_REQUIRED}   # "blocked on human/credential"
WORKING → {COMPLETED, FAILED, CANCELED, REJECTED}        # REJECTED: agent reddi birinci sınıf
+ HIBERNATED   # default bekleme hâli: terminate değil (KeyKOS/E2B; 4sn/GiB kaydet, ~1sn dön)
+ EVOLVING     # self-modification sandbox'ında fork-modify-validate-merge (SELF-IMPROVEMENT-SPEC)
```

- Terminal task'a mesaj → typed error (A2A kuralı).
- `tb_agent_send` blocking (terminal-veya-interrupted'a kadar) ve non-blocking (poll/subscribe/webhook-bridge) modları destekler.

## 3. Agent İmaj Formatı **[ÖNERİ — ".taf", Letta .af envanterinin kernel-tamamlanmışı]**

| .af'tan alınan | TABOS düzeltmesi |
|---|---|
| model config, mesaj geçmişi + in_context bayrakları, system prompt, memory blocks, tool kuralları + kaynak + JSON şemaları, env | in_context bayrakları kernel context-manager'ın malıdır, serialize edilen uygulama verisi değil |
| — | **Tüm memory tier'ları dahil** (archival dahil): checkpoint = tam durum |
| secrets null'lanır | **secret = load-time çözülen capability referansı** |
| — | FS delta + task durumları + budget + handle tablosu dahil (AgentProcess'in tamamı) |
| — | İmza: manifest JWS (A2A Agent Card modeli); imaj = kurulum/fork/suspend/migrate/repro-eval birimi (ELF+core-dump rolü) |

.af **import uyumluluğu** ucuz ekosistem kazancı olarak hedeflenir [AÇIK: dönüştürücü kapsamı].

## 4. Spawn Protokolü **[KARAR]**

1. Çağıran `tb_agent_spawn(manifest)` der; manifest imzası doğrulanır (kernel/trusted loader).
2. Kernel manifest'in **prefix tablosunu** handle setine çevirir (Fuchsia namespace transfer); tabloda olmayan kaynak agent için *yoktur*.
3. Agent **tek bootstrap channel** ile doğar (Zircon); kalan her şeyi o kanaldan ister — yetki seti doğum anında numaralandırılabilir.
4. Bütçe: çağıranın budget handle'ından `tb_budget_split` ile dilim — devredilebilir, iç içe, geri alınabilir [AÇIK: dolar+token kompozisyonu].
5. Fork çeşidi: `tb_agent_fork` paylaşımlı prefix'i scheduler'a yapısal ipucu olarak geçirir (SGLang fork-hint: ortak system prompt/tool tanımları bedava cache hit).
6. Spawn maliyet hedefi: **<50 ms** (unikernel hattı ~1 ms boot + imaj yükleme; E2B <200 ms çıtasının altı).

## 5. Scheduling **[ÖNERİ — detay ARCHITECTURE §5-6]**

Özet bağlama: quantum = decision cycle (kesinti yalnız cycle sınırında); impasse trap'leri otomatik child-context; QoS `INTERACTIVE/PIPELINE/BULK`; cache-topology-aware dispatch + aging; billing-aware preemption (lokal serbest, metered remote run-to-completion eğilimli); token-pressure'da admission control. Watchdog: tekrarlanan-eylem (>3) ve eylem-sayısı (>30) sezgileri `reflect` sinyali üretir (Reflexion) — sinyal, cycle sınırında teslim edilir.

## 6. IPC ve Oturum İçi İletişim **[KARAR — katmanlama; ÖNERİ — mekanizmalar]**

- **Kernel lehçesi tek**: correlated request/response + notification + cancellation + capability-passing channel + durable Task + sıralı-replay'li Stream ([ARCHITECTURE §9](ARCHITECTURE.md)).
- **Dosya yüzeyi**: agent A, `cat /agent/B/status` okur; `/agent/B/inbox`'a yazar — koordinasyon için yeni API icat edilmez (Plan 9). Typed kanallar isteyen `agent:` scheme'inden channel açar.
- **Blackboard**: `memory:session/<sess>` + paylaşımlı `blocks:` — Letta'nın "update once, visible everywhere" deneyimi, kernel CAS/watch ile yarışsız. Üretici/tüketici: uyanık-agent ile sleep-time-agent aynı blokları paylaşır.
- **Event fan-out**: bir Task'ın stream'ine N gözlemci; herkes aynı olayları aynı sırada alır; bir stream'in kopması diğerini etkilemez (A2A kuralı) — supervisor/auditor/peer'ların ortak izleme temeli.
- **Dış protokoller**: MCP (tool/data düzlemi), A2A (peer delegasyon), ACP (REST/multipart; offline package-discovery fikri pakete alınır), ANP (DID kimlik; humanAuthorization kapısı) — hepsi userspace bridge; webhook'lar NAT'lı uçlar için kernel stream aboneliğine çevrilir [AÇIK].

## 7. Kimlik ve Güven **[ÖNERİ]**

- Agent = kernel principal; her task için **türetilmiş, en-az-yetkili, süreli alt-kimlik** (ANP çok-DID stratejisi).
- Anahtar nezareti: keyring servisi; `EMIT_EXTERNAL` etiketli op'lar (ödeme, mahremiyet, geri-alınamazlar) **insan-onaylı ikinci keyring**den imza ister (humanAuthorization; MCP elicitation accept/decline/cancel — kısıtlı şema kernel'da ucuz doğrulanır).
- Karşılıklı-şüpheli işbirliği: capability modeli sayesinde "senin verin × benim agent'ım, iki yön de sızdırmaz" — confinement'ı doğrulanabilir agent şablonları (KeyKOS factory deseni) [AÇIK: doğrulama mekanizması].

## 8. Çoklu-Agent Oturumu **[ÖNERİ]**

`Session` nesnesi = üye agent handle'ları + `memory:session` tier'ı + paylaşımlı block'lar + task fan-out stream'leri + ortak bütçe havuzu (opsiyonel oversubscribe, Anthropic workspace deseni). Topoloji (kim kime mesaj atar) **versiyonlu, evolvable nesnedir** — self-improvement'ın evrim hedeflerinden biri (survey 2508.07407'nin topology-evolution sınıfı). Tek-agent oturumu = |üye|=1 özel hâli; ayrı kod yolu yoktur.
