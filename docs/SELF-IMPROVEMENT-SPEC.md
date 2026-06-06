# TABOS Self-Improvement Spesifikasyonu

> Durum: v1.0 taslak — **[KARAR] / [ÖNERİ] / [AÇIK]** işaretli.
> Dayanak: [RESEARCH-REPORT §7](RESEARCH-REPORT.md#7-self-improvement--os-servisi-olarak) · İlgili: [ARCHITECTURE](ARCHITECTURE.md) · [MEMORY-SPEC](MEMORY-SPEC.md) · [AGENTS-SPEC](AGENTS-SPEC.md)

---

## 0. İlke: Üç Yasa, kernel-zorlamalı öncelik sırasıyla **[KARAR]**

Self-improvement commit pipeline'ının her adımında [arXiv:2508.07407]:

1. **ENDURE** — güvenlik denetimleri geçilmeden hiçbir değişiklik;
2. **EXCEL** — mevcut yetenek suite'inde regresyon yoksa;
3. **EVOLVE** — ancak o zaman merge.

Alt basamak üst basamağı asla override edemez. Bu sıra konfigürasyon değil ABI'dir.

## 1. Frozen Kernel / Evolving Userspace **[KARAR — DGM emsali]**

- **Donmuş (agent'ın self-modification kapsamı DIŞI):** kernel, evaluator'lar/güvenlik dedektörleri, evrim makinesi (arşiv bakımı, parent seçimi), bütçe muhasebesi, audit/lineage log'u.
- **Evrilen (default yazma yetkisi):** agent'ın *kendi* config alt-ağacı — prompt'lar, tool seçimi, workflow kodu, memory içeriği. Kapsam genişletme (paylaşılan tool'lar, başka agent'lar, lokal model ağırlıkları) explicit capability grant.
- **Ölçen-ölçülen ayrımı** [KARAR]: DGM'de görünür evaluator fiilen hack'lendi (loglamayı söküp dedektörü bypass eden node 114); gizlide hacking azaldı. TABOS'ta `Evaluator` nesneleri agent'ın hak maskesinde *hiç görünmez*; kernel'ın agent I/O'suna enjekte ettiği instrumentation işaretleri agent'ın yazma yetkisinin dışındadır; tek görünür metrik Goodhart'lanacağından **çoklu held-out evaluator** default'tur.

## 2. Evrim Servisi API'si **[ÖNERİ — survey taksonomisi imza olur]**

```
tb_evolve_request = {
  locus:  context | tool | architecture | model,   # WHAT  (2507.21046)
  timing: intra | inter,                            # WHEN  (test-time)
  optimizer: reward | imitation | population,       # HOW   (+ S,H çifti: 2508.07407)
  budget: Budget handle                             # zorunlu — bütçesiz evrim yok
}
```

- **Default'lar weight-free ve LLM-agnostik**: context + tool evrimi, inter-test-time (her backend'de çalışır — Reflexion %91 HumanEval'i ağırlıksız aldı).
- `model` locus'u yalnız lokal backend'de anlamlı, capability-kapılı, `BULK`-sınıfı (EvolveR'ın GRPO hattı pluggable şablon).

## 3. Default-On Katman: Reflection **[KARAR]**

- Kernel watchdog'u takılmayı sezer (aynı eylem >3, eylem >30 — Reflexion sezgileri) → `reflect` sinyali.
- Sözel self-reflection **bounded reflection tier'ına** yazılır (default son-k penceresi; ham trajectory'den ayrı tier — +%8 ablation kanıtı).
- Maliyet: yalnız inference; her agent'ta açık gelir.

## 4. Sleep-Time Sınıfı **[KARAR — Letta ~5× kanıtı]**

- Konsolidasyon/damıtma agent'ları **idle inference kapasitesine** `BULK` QoS ile yerleşir; tetikler kernel-düzeyi: every-N-step (default 5), on-idle, on-memory-pressure.
- Uyanık-agent ile uyuyan-agent paylaşımlı block'lar üstünden konuşur ([AGENTS-SPEC §6](AGENTS-SPEC.md)).
- Token bütçesi cgroup-analog sınırlı; "yüksek frekans pahalı + azalan getiri" uyarısı default frekansı korur [AÇIK: ampirik bütçe modeli].

## 5. Skill Tier'ı (T4) **[ÖNERİ]**

- **Skill = {çalıştırılabilir kod (WASM component), NL açıklama, açıklama-embedding'i, WIT tipli arayüz, utility sayaçları, lineage}** (Voyager + Component Model).
- **Verification-before-commit** [KARAR]: skill, ayrı verifier-agent'ın başarı denetiminden geçmeden registry'ye giremez; bounded retry (default 4 — Voyager); ablation gerekçesi: self-verification yokken keşif −%73.
- **Trust-gated promotion** (ACT-R production compilation): derlenen/öğrenilen skill **utility 0'dan** başlar; deliberatif yolu ancak tekrar tekrar kanıtlayınca yener — built-in gölge-mod/canary. Utility update: `U += α(R−U)`, α=0.2 default, zaman-iskontolu ödül; credit assignment kernel plumbing'idir.
- **Skill compiler** (Soar chunking): impasse-çözüm trace'lerinden spekülatif derleme; koşul **bağımlılık izi**dir (tüm context değil — overfit önlemi); LLM çağı karşılığı: provenance, tool-call ve memory-read sınırlarında kernel'ca otomatik kaydedilir [AÇIK: NL zincirlerinde yeterli granülarite].
- **Curse-of-abundance yönetimi day-one** [KARAR]: namespace'ler, usage-ranked retrieval, kota; **memory-GC daemon'ı** dedup (embedding + LLM eşdeğerlik) → merge → utility-pruning `s=(c_succ+1)/(c_use+2)` eşik altını budar (EvolveR).
- **Composability kuralları kaynak-sınıfı başına** (ACT-R buffer-tipi matrisi): idempotent read'ler serbest birleşir; `EMIT_EXTERNAL` etiketli side-effect'li adımlar muhafazakâr/birleşmez.

## 6. Curriculum Daemon'ı **[ÖNERİ]**

Görev önerisi OS servisidir (Voyager: rastgele curriculum'a karşı −%93): girdileri zaten kernel'da — agent durumu introspection ağacı, tamamlanan/başarısız task ledger'ı (memory tier'ları). **Failed-task retry kuyruğu default memory yapısıdır.** Öneri modeli pluggable; durum+tarih beslemesi standart kernel arayüzü.

## 7. Popülasyon Evrimi: Arşiv **[ÖNERİ — DGM şablonu]**

- Agent sürümleri **immutable, versiyonlu snapshot'lar** olarak popülasyon deposunda (CoW dosya sistemi snapshot'ları doğal eşleme; .taf imajları).
- **Parent seçimi**: performansla orantılı, çocuk sayısıyla ters orantılı; herkes sıfır-dışı olasılık taşır (stepping-stone etkisi: erken keşifler çok sonra işe yarar).
- **Viability gate** kernel'da: derlenir + kendi kodunu düzenleme yetisini korur; geçemeyen arşive giremez.
- **Staged evaluation** default politika şablonu: ucuz probe (10 görev) → orta (50) → tam suite (eşik + arşiv-top-2 şartıyla) — maliyet gerçeği: DGM koşusu ~2 hafta / ~22.000 USD; bu yüzden evrim `BULK`, bütçeli, kesinlikle arka plandır.
- Kernel her sürüm için **maliyet + performans** izler; seçim maliyet-düzeltilmiş yeteneği optimize edebilir (ikisi korele değil — DGM ölçümü).

## 8. Self-Modification İşlemi **[KARAR — DGM güvenlik mekaniği]**

```
fork (izole sandbox; default-deny network; CPU/wall-clock/token kotalı)
  → modify (yalnız kendi alt-ağacı)
  → validate (ENDURE: güvenlik suite → EXCEL: regresyon suite — held-out)
  → merge (insan-onay hook'u: yüksek-etki sınıfında zorunlu)
```

Her adım **append-only lineage log'una** (arşive bağlı) yazılır; rollback = snapshot restore; post-hoc audit = log yürüyüşü. Gevşetmeler config flag değil capability grant'tir.

## 9. Telemetri **[AÇIK]**

Alan "snapshot-based" değerlendirmede; nesiller-arası güvenlik kayması ölçülmüyor. TABOS default'u: her agent sürümü için sürekli güvenlik metrikleri (Safety Score / Risk Ratio / Leakage Rate sınıfı — 2507.21046 Tablo 6) kernel'ca yayınlanır; longitudinal benchmark tasarımı açık iş.
