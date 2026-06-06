# TABOS Memory Spesifikasyonu (Default Memory Yapısı)

> Durum: v1.0 taslak — **[KARAR] / [ÖNERİ] / [AÇIK]** işaretli.
> Dayanak: [RESEARCH-REPORT §4](RESEARCH-REPORT.md#4-memory-literatürü--default-memory-yapısının-hammaddesi) · İlgili: [ARCHITECTURE](ARCHITECTURE.md) · [AGENTS-SPEC](AGENTS-SPEC.md) · [SELF-IMPROVEMENT-SPEC](SELF-IMPROVEMENT-SPEC.md)

---

## 0. İlke

**Memory, TABOS'ta bir kütüphane değil kernel garantisidir.** Her agent doğduğunda aşağıdaki tier seti otomatik var olur; hiçbir framework kodu gerekmez. Kernel *depoyu, indeksi, kotaları, tutarlılığı ve provenance'ı* garanti eder; *neyin önemli olduğuna karar veren zekâ* (enrichment, op seçimi, damıtma) pluggable userspace servislerindedir (LLM-agnostiklik: exokernel ayrımı — koruma kernel'da, politika dışarıda).

## 1. Tier Mimarisi **[KARAR — survey'in beşli yakınsamasından türetilmiş T0–T5 + BLOCKS yapısı; gerekçe: 84 mimari, arXiv:1610.08602]**

```
T0  CONTEXT REGISTERS   ACT-R buffers: adlandırılmış, sınırlı, tipli kayıt yuvaları
                        (goal, retrieval, percept, tool-result, …). Prompt bunlardan
                        materialize edilir — sınırsız context blob'u YOK.
T1  WORKING             Soar WM: state-köklü graf; erişilemeyen otomatik GC;
                        i-support (gerekçe düşünce otomatik geri çekilir) / o-support ayrımı.
T2  EPISODIC JOURNAL    Otomatik flight-recorder (agent eylemi gerektirmez — Soar EpMem);
                        kayıpsız, append-only, bi-temporal; read-your-writes ANLIK.
T3  SEMANTIC STORE      Damıtılmış fact/not kayıtları; embedded store (SQLite-emsal:
                        milyonlarca node'da sub-ms, <1KB/fact); activation-ranked retrieval.
T4  PROCEDURAL / SKILL  Çalıştırılabilir skill'ler + damıtılmış ilkeler; yazma ayrıcalıklı
                        (CoALA risk asimetrisi: WRITE_PROCEDURAL ayrı hak; verification-
                        before-commit — bkz. SELF-IMPROVEMENT-SPEC).
T5  ARCHIVAL / PARAMETRIC  (opsiyonel modüller) Vector-archival (Letta tarzı) ·
                        graph tier (Zep/Mem0g — temporal sorgular için opt-in) ·
                        parametric (fine-tune/knowledge-edit; yalnız lokal backend, BULK).
+   BLOCKS              Letta memory-block tier'ı: adlandırılmış, kotali, N agent'ın
                        context'ine MAP edilebilen pinned segmentler; CAS/CRDT yazım
                        semantiği (last-write-wins kütüphane hatası kernel'da çözülür).
```

Sapma gerekçeleri (survey'in kendi kuralı: *deviation needs justification*): survey'in **sensory** tier'ı TABOS'ta ayrı tier değildir — percept/ingest akışı T0 register'larına düşer (ACT-R perceptual buffer modeli); T5 ve BLOCKS, beşli çekirdeğin (T0–T4) üstüne opsiyonel/eklenti katmanlardır.

Union-namespace ergonomisi: session-scratch tier, kalıcı tier'ın üstüne bind edilir; `tb_recall` union sırasında düşer ([ARCHITECTURE §3](ARCHITECTURE.md)).

## 2. Kayıt Şeması **[ÖNERİ — A-MEM + Zep + GA sentezi]**

`MemRecord` (kernel-sabit alanlar; inode analojisi):

| Alan | Tip | Kaynak/desen |
|---|---|---|
| `id`, `content` | — | ham içerik (metin/MIME-parçalı — ACP dersi) |
| `t_created, t_expired` | transaction timeline | **bi-temporal zorunlu** (Zep) |
| `t_valid, t_invalid` | event timeline | çelişki = invalidate, silme değil |
| `importance` | int 1-10 | yazım anında tek LLM çağrısı (GA "poignancy") |
| `embedding` | vec | provider pluggable |
| `keywords, tags, context` | derived | enrichment userspace servisi (A-MEM; lokal 1B model ~1.1 sn/op) |
| `links[]` | typed | `cites` (derived→source: halüsinasyon denetimi — GA reflection), `relates`, `supersedes` |
| `provenance` | enum+ref | inside-trial / cross-trial / external (survey 2404.13501) + üreten agent/task |
| `access` | {count, last_k_ts[k=10]} | base-level activation O(1) durumu (ACT-R/Petrov) |
| `utility` | {c_succ, c_use} | s=(c_succ+1)/(c_use+2) — sonuç telemetrisinden kernel doldurur (EvolveR) |
| `acl` | namespace ref | §7 |

**Yazma transactional'dır**: bir insert komşu k kaydı evrimleştirebilir (A-MEM memory evolution) → çok-kayıt atomik güncelleme + eski sürümler geri getirilebilir (versioning).

## 3. Operasyon ABI'si **[ÖNERİ]**

- **Üç syscall ailesi** (survey'in üç OPERATIONS sınıfı): `tb_mem_write` / `tb_mem_read` / `tb_mem_manage`; CoALA üçlüsü `tb_recall`/`tb_reflect`/`tb_learn` bunların üstünde şeker.
- **Update kararı dört-op sözlüğüyle**: `ADD / UPDATE / DELETE(→tombstone) / NOOP` — politika kararını veren LLM "oracle"ı pluggable (function-calling arabirimi, Mem0); op'u *yürüten* kernel'dır.
- **Retrieval üç-aşamalı pipeline'dır, monolitik search değil** (Zep): ① aday arama — hibrit default: lexical (BM25) + dense (cosine) + graph/BFS paralel; ② rerank — pluggable: RRF/MMR/cross-encoder/node-distance; ③ context constructor — şablonlu, geçerlilik tarih aralıklı.
- **Default sıralama (ağırlıklı toplam)**: `score = w_a·BLA(d=0.5) + w_r·relevance + w_i·importance` (bileşenler min-max normalize, default w=1) — toplamsal form, GA'nın doğrulanmış skoruna (α_rec·rec + α_imp·imp + α_rel·rel, tüm α=1) ve ACT-R'ın kendi aktivasyon denklemine (A = B + S + P + ε) sadıktır; BLA(d=0.5) hem Soar hem ACT-R'ın yakınsadığı, 50 yıllık en iyi doğrulanmış sabit; spreading activation (buffer-içeriğinden priming, fan-effect cezalı), partial match ve noise **default KAPALI** (ACT-R muhafazakârlığı).
- **Finsts** [KARAR]: kernel, agent başına bounded + süreli "az önce döndürüldü" kümesi tutar ve `exclude_recent` / `retrieve_next` iterasyon semantiği sunar — RAG aynı-sonucu-döndürme döngüsünün 40 yıllık kırıcısı (ACT-R 4/3sn; TABOS default'u oturum uzunluğuna ölçekli [AÇIK]).
- **İndeksleme kapsamı** [ÖNERİ]: default indeks agent *çıktılarını da* kapsar, yalnız kullanıcı girdilerini değil — Zep'in single-session-assistant regresyonu (−%17.7, gpt-4o) türetilmiş tier'ların asistan-tarafı ayrıntıyı kaybettiğini gösterdi.
- **Copy-on-retrieve** [ÖNERİ]: retrieval, working memory'ye *kopya* enstantiye eder (Soar LTI/STI ayrımı); uzun-vadeli depo yalnız explicit commit'le değişir — kazara in-place mutasyon yok.
- **Erişim metadata'sı okuma yolunda yazılır** → relatime-tarzı batch'leme [AÇIK].

## 4. Konsolidasyon ve Reflection **[ÖNERİ]**

- **Tetik cron değil importance-akümülatörüdür** (GA: eşik 150, günde 2-3 tetik): kernel agent başına gelen importance toplamını sayar; eşik aşımında `BULK` sınıfı reflection job'ı planlar (dirty-page writeback analojisi).
- Reflection çıktıları `cites` linkli olarak T3'e döner; reflection-üstüne-reflection ağaçları serbest.
- **Async consolidation daemon** (kswapd analojisi — Mem0'ın async summary refresher'ı): özetler, dedup (embedding + LLM eşdeğerlik), merge, demotion; agent'ın kritik yolunu asla bloklamaz.
- **Sleep-time compute** bu daemonun genelleşmiş hâlidir; idle inference kapasitesine `BULK` olarak yerleşir (~5× ölçülmüş geri ödeme — [SELF-IMPROVEMENT-SPEC §4](SELF-IMPROVEMENT-SPEC.md)).

## 5. Tutarlılık ve Kota **[KARAR — ilkeler]**

- **Read-your-writes, T2 (raw episodic) üzerinde ANLIKTIR.** Türetilmiş tier'lar (T3+, graph, communities) **görünür epoch/freshness işareti** taşır; agent güvenmeden önce sorgulayabilir. (Zep'in saatlerce ingestion lag'i + RYW'sizliği karşı-örnek.)
- **Write-amplification token-cinsinden kotalıdır** (disk kotası analojisi): sınırsız LLM-türetme 20×'ten fazla şişirebiliyor (Zep ölçümü: 26K→600K+); space-bank tarzı hiyerarşik bütçe (KeyKOS).
- p95 retrieval bütçesi **<200 ms** (Mem0 kanıtladı); **escape hatch**: yüksek-bahisli sorgu için raw-episode replay her zaman adreslenebilir (10-17 sn'lik bedeliyle — full-context ~5 J-puanı tavan farkı).

## 6. Forgetting **[ÖNERİ — alanın çözmediği yer, TABOS tasarımı]**

Hiçbir birincil sistem test edilmiş gerçek silme uygulamıyor; yakınsanan güvenli kompozisyon:

1. **Skor-çürümesiyle demotion** (GA decay × BLA): kayıt tier'lar arasında aşağı iner (T3→T5 archival), kaybolmaz.
2. **Tombstone, silme değil** (Zep+Mem0g konsensüsü): `t_invalid` set edilir; tarih korunur; temporal sorgular çalışır.
3. **Hard delete yalnız ayrıcalıklı explicit op** (privacy/compliance; insan-onay kapısına etiketli).
4. **Soar'ın iki itiraf edilmiş boşluğu kernel'da kapanır**: sınırsız journal için default compaction/özet tier'ı + kanonik journal üstünde pluggable ikincil indeksler (lineer-tarama worst-case'i).

## 7. Çok-Agent Memory Namespace'leri **[ÖNERİ — greenfield; literatürde standart yok]**

Survey §8.2 bu alanı açık ilan ediyor; TABOS tasarımı:

```
memory:private/<agent>/…    yalnız sahibi; default ev
memory:session/<sess>/…     oturumdaki agent'lar (blackboard deseni: paralel yazarlı
                            paylaşımlı bilişsel durum — 84-mimari survey'inin kanıtlı yapısı)
memory:world/…              kurulum-çapı bilgi; READ herkese, WRITE küratörlü
blocks:<name>               pinned paylaşımlı segmentler; CAS/versiyonlu yazım + watch
```

- Erişim capability'yle (handle+rights); `RECALL` hakkı tier başına ayrılabilir.
- Session tier'ında yazım çakışması: kayıt-düzeyi CAS + çakışmada her iki sürümü bi-temporal tutup `supersedes` linki [AÇIK: CRDT mi CAS mı — prototip ölçümü].
- Timing yan-kanalı: farklı trust-domain agent'ları arasında prefix/embedding cache paylaşımı kapalı default [AÇIK].

## 8. Benchmark Gerçeği **[AÇIK]**

Mevcut benchmark'lar (DMR doymuş %98; LOCOMO konuşma-QA; DialSim'de tüm sistemler F1<4) OS-ömrü agent memory'sini ölçmüyor. TABOS kendi değerlendirme koşumunu tanımlamalı: tool-use trace'leri, kod görevleri, cross-task skill transferi, multi-agent oturumları, haftalar süren yaşam döngüleri. ([OPEN-QUESTIONS §Memory](OPEN-QUESTIONS.md))
