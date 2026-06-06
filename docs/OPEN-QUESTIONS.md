# TABOS Açık Sorular

> Durum: v1.0 · Öncelik: **P0** = spec donmadan kapanmalı · **P1** = Faz-1 prototipten önce · **P2** = ilgili faz başlamadan önce
> Kaynak: üç araştırma dalgasının alan-bazlı openQuestions çıktıları ([`../research/raw/`](../research/raw/)) + döküman yazımında doğan sorular.

---

## A. Mimari / Kernel

| P | Soru | Bağlam |
|---|---|---|
| P0 | **Kernel-vs-userspace sınırı lokal KV yönetiminde nerede?** Kernel PagedAttention-tarzı block table'ları kendisi mi tutar, yoksa vLLM/SGLang'i userspace engine-server olarak schedule mi eder? | Tüm kaynak sistemler userspace; kernel-resident KV pager'ın kazanç/kaybını kimse ölçmemiş |
| ✅ KARAR | **Substrat: Firecracker/KVM-sınıfı VMM üstünde guest, tek-vCPU (Mirage), x86_64 LinuxBoot / aarch64 PE-Image.** Bare-metal değil; Unikraft C-TCB'si reddedildi (saf-Rust node image). Detay + executable DoD: [KERNEL-FOUNDATION-SPEC](KERNEL-FOUNDATION-SPEC.md) §0,§2 | Çözüldü 2026-06-07 |
| P1 | seL4 formal verification yaklaşımı handle katmanımız için gerçekçi mi; MCS verification'ının tamamlanma durumu takip edilmeli | seL4 MCS henüz proof-coverage dışı |
| P1 | 9P-tarzı protokolün yüksek-latency linklerde gevezeliği (walk/open/read): remote memory tier'ları ve model uçları için batched/pipelined uzantı mı, LISAfs-tarzı protokol mü? | gVisor 9P'den taşındı |
| P1 | Agent manifest şeması: Fuchsia .cml mi, OCI runtime spec mi, WASI component imports mı taban alınır, yoksa yeni şema mı? | Plan 9'un serileştirilemeyen namespace itirafı + Fuchsia emsali |
| P1 | AIOS'un fiili syscall kataloğu (Table 2) `agiresearch/AIOS` kaynak ağacından doğrulanmalı — `tb_` adlandırması donmadan | HTML'de tablo görüntüye gömülü; ham veride açık soru |
| 🎯 GATE | <50 ms spawn hedefi **validation-gate** olarak M0/M3 DoD'sine bağlandı (Hermit saf-Rust unikernel Firecracker'da boot ediyor — emsal var); ölçüm düşerse Firecracker+minimal-guest'e geri çekil | [KERNEL-FOUNDATION-SPEC §9](KERNEL-FOUNDATION-SPEC.md) |
| P2 | Çok-node federasyon: scheme/handle namespace'leri makineler arası nasıl köprülenir — Plan 9 import mu, A2A discovery mi, network channel'dan capability-passing mi; inter-kernel güvende 9P auth/attach'in yerini ne alır? | Swarm senaryosu |
| ✅ KARAR | **VMM egemenliği = kendi `tb-vmm`'imiz** (rust-vmm tabanlı, `tb-boot v0` kontratı); stock Firecracker yalnız bootstrap loader. virtio=OASIS açık standardı (değiştirilebilir sürücü). Detay: [SOVEREIGNTY](SOVEREIGNTY.md) | Çözüldü 2026-06-07 |
| P2 | Bare-metal hedefi ne zaman (varsa)? GPU yan-kanalları ayrı izolasyon istiyor mu? (tb-vmm sonrası doğal uzantı) | Bytecode Alliance Spectre itirafı; GPU side-channel literatürü taranmadı |

## B. Capability / Güvenlik

| P | Soru | Bağlam |
|---|---|---|
| P0 | **LLM'in ürettiği metin ile kernel handle'ı arasındaki bağ**: tool-call metnindeki hangi temsil unforgeable token'a bağlanır; confused-deputy (prompt-injection meşru capability'yi kötüye kullandırır) nasıl sınırlandırılır — rights mask blast-radius'u sınırlar ama *niyeti* kodlamaz | İzolasyon araştırmasının en sivri sorusu |
| P0 | Capability granülaritesi: MCP feature-level + A2A skill-level + ANP service-level deklarasyonlarını kayıpsız taşıyan tek hiyerarşi tasarlanabilir mi? | Bridge'lerde lossy çeviri riski |
| P1 | KeyKOS-tarzı universal persistence × revocation × dış (transactional olmayan) kaynaklar: restore edilen agent'ın elindeki remote-API/model-session handle'ları geri sarmadı — sözleşme ne? | [ARCHITECTURE §8](ARCHITECTURE.md) |
| P1 | WASI 0.2/0.3 resource handle'ları attenuated re-export'u (yetkiyi bağımlılık ağacına zayıflatarak geçirme) artık native veriyor mu? 2019 itirafının güncel durumu | Component Model hızla evrildi |
| P1 | Factory-deseni (sızdırmazlığı doğrulanabilir agent şablonları) hangi mekanizmayla doğrulanır? | Karşılıklı-şüpheli işbirliği vaadi buna yaslanıyor |
| P2 | Webhook'lu dış protokoller NAT'lı/edge uçlarda: kernel-managed relay daemon'ı mı, bridge'de stream-aboneliğine çeviri mi? | A2A push-notification varsayımı |

## C. Memory

| P | Soru | Bağlam |
|---|---|---|
| P0 | **Çok-agent paylaşımlı memory'nin çakışma semantiği**: kayıt-düzeyi CAS mi, CRDT merge mi; Soar i-support otomatik-geri-çekilmesi eşzamanlı yazarlar altında hangi tutarlılık modelini ima eder? | Literatürde standart yok — greenfield |
| P0 | Graph tier'ın yeri: Zep LongMemEval'de +%18.5 diyor, Mem0 single/multi-hop'ta kaybettiğini ve 2-3× maliyeti ölçüyor, A-MEM graph DB'leri katı buluyor — default'ta var mı, opt-in mi? (Mevcut karar: opt-in; prototipte ölçülecek) | Çelişen birincil kaynaklar |
| P1 | Eviction/forgetting default'unun benchmark'ı: skor-çürümeli demotion + tombstone bileşimi neyle ölçülür? OS-ömrü memory benchmark'ı tasarlanmalı (mevcutlar: DMR doymuş, DialSim'de herkes F1<4) | [MEMORY-SPEC §8](MEMORY-SPEC.md) |
| P1 | Write-path'te lokal küçük model: 1B-sınıfı enricher/op-decider frontier'a karşı extraction/dedup/importance/op-seçiminde ne kadar doğruluk kaybeder? (A-MEM 1.1 sn/op'u ölçtü, doğruluk farkını ölçmedi) | Default enricher kararı |
| P1 | Zaman sabitlerinin yeniden kalibrasyonu: insan-kalibrasyonlu sabitler (d=0.5 saniyeler üstünden, finst 3 sn, decay 0.995/saat) LLM-agent zaman ölçeğinde wall-clock mı, decision-cycle mı, token mu cinsinden tanımlanır? | Bilişsel mimari taşıması |
| P1 | T0 register seti: kaç register, register başına token bütçesi ne; hard cap (ARCADIA 3-6) mı soft activation eşiği mi? | ACT-R 1-chunk insan kalibrasyonu |
| P1 | Dosya sistemi: semantic+versioned VFS mi, düz object store mu; T5 archival ile tek storage manager'da birleşme (`fs:` scheme kontratı — Letta/AIOS bulguları) | [ARCHITECTURE §3](ARCHITECTURE.md) |
| P2 | Erişim metadata'sının (last-k timestamps) okuma yolunda yazılması: relatime-tarzı batch'leme yeterli mi? | Read-path write traffic |
| P2 | Parametric tier promotion kriterleri: textual→parametric ne zaman taşınır; catastrophic-forgetting bekçileri ne? | Survey: under-researched |
| P2 | Utility vs activation iki ayrı sıralama düzlemi mi (skill trust / memory salience), tek ledger mı? | ACT-R iki ayrı subsymbolic sistem tutuyor |

## D. Scheduling / Token Ekonomisi

| P | Soru | Bağlam |
|---|---|---|
| P0 | **Cache-locality × fairness**: SGLang starvation'ı future-work bıraktı; hangi aging/virtual-runtime mekanizması default? | Scheduler spec'inin çekirdeği |
| P1 | OTPM rezervasyonu: çıktı uzunluğu öngörülemezken eşzamanlı agent'lara output bütçesi nasıl ayrılır (Anthropic OTPM yalnız üretileni sayar, max_tokens'ı değil)? | Over/under-commit ikilemi |
| P1 | Lease-renewal ekonomisi: idle-süre dağılımına göre 5dk-touch vs 1sa-TTL break-even politika fonksiyonu (fiyatlar belli, eğri çıkarılmalı) | Remote driver politikası |
| P1 | Recompute-vs-fetch crossover: tier bandwidth'ine karşı prefill hızı — deployment başına ölçüm gerektiren default eğri | Mooncake model vermiyor |
| P1 | Token bütçeleri devredilebilir capability olarak: dolar + token tek capability tipinde nasıl birleşir; iç içe ve geri alınabilir delegasyon (workspace deseninin genelleşmesi) | `tb_budget_split` tasarımı |
| P2 | Remote DAG kaybı: public API'ler request-level kalırken speculative dispatch/stream-pipelining client-side ne kadarını geri kazanır? | Parrot kazancı self-hosted'da |
| P2 | Farklı trust-domain'ler arası prefix-cache paylaşımı: timing yan-kanalı ("bu prefix'i başka agent görmüş mü") — intra-host izolasyon politikası | Hiçbir kaynak ele almıyor |

## E. Self-Improvement

| P | Soru | Bağlam |
|---|---|---|
| P0 | **Introspection × hidden-evaluator gerilimi**: agent'ın okuyabildiği kernel durumu ile okuyamayacağı evaluator seti arasındaki sınır tam olarak nereden geçer? | Agent-native OS şeffaflık vaadiyle Goodhart savunması çelişiyor |
| P1 | Evrim işlerinin bütçe birimi ve ödeyeni: token mu dolar mı wall-clock mu; çok-agent oturumunda fatura kime? (DGM gerçeği: ~22k USD/koşu) | `tb_evolve_request.budget` |
| P1 | EXCEL yasasının regresyon suite'i: agent'ın görev dağılımı kayarken per-agent yetenek testi nasıl güncel tutulur? | Merge kapısının dişleri |
| P1 | NL reasoning zincirlerinde skill-compiler provenance granülaritesi: tool-call/memory-read sınırları yeterli mi, token-düzeyi atıf gerekir mi? | Soar backtrace'in LLM çevirisi |
| P1 | Depolama birleşimi: DGM arşivi + Reflexion buffer'ı + Voyager skill lib + EvolveR ilke deposu tek tiered substrat üstünde farklı retention/index politikalarıyla yaşayabilir mi? (Mevcut tasarım: evet, T2-T4; doğrulanmalı) | [MEMORY-SPEC](MEMORY-SPEC.md)×[SELF-IMPROVEMENT-SPEC](SELF-IMPROVEMENT-SPEC.md) |
| P1 | Sleep-time ekonomisinin ampirik bütçe modeli (Letta sayı vermiyor: "expensive, diminishing returns") | Default-on kararının maliyet tarafı |
| P2 | Longitudinal güvenlik telemetrisi: nesiller-arası kayma için hangi metrik seti kernel default'u olur (Safety Score/Risk Ratio/Leakage Rate sınıfı)? | Alan snapshot-based |
| P2 | ANP müzakere-üretimi adapter kodu: skill sandbox+verification hattından geçmesi yeterli mi? | Userspace üretilen kod kernel'a komşu |

## F. Protokoller / Ekosistem

| P | Soru | Bağlam |
|---|---|---|
| P1 | MCP tasks (SEP-1686, deneysel) A2A 9-durum makinesiyle yakınsayacak mı? Kernel task ABI'sini dondurmadan izle | İki standart tek şekle inerse bridge basitleşir |
| P1 | ACP'nin A2A'ya konsolidasyonu (orta-2025 duyumları) birincil kaynaktan doğrulanmalı; ACP sunset ise offline-discovery + await/resume doğrudan içselleştirilir | Bridge mi, yerli özellik mi |
| P1 | A2A discovery well-known URI'sinin normatif son hâli (agent.json → agent-card.json göçü) | Discovery daemon spec'i |
| P2 | Survey-sonrası protokoller (AGNTCY, Agora arXiv:2410.11905, AP2/payments): kernel-ilgili yeni primitif getiren var mı? | Periyodik tarama |
| P2 | AIOS Cerebrum agent-hub mekaniği derin okunmalı (paket/dağıtım/keşif) — TABOS paket yöneticisi tasarımına girdi | Faz 4 |
| P2 | E2B latency iddialarının (80 ms vs <200 ms) bağımsız benchmark'ı — başarı kriteri #1'in çıtası ölçümle sabitlenmeli | self-host repo'suyla |
| P2 | .af import dönüştürücüsünün kapsamı: hangi alanlar kayıpsız taşınır; archival/secret boşlukları nasıl doldurulur? | [AGENTS-SPEC §3](AGENTS-SPEC.md) |

## G. İsim / Marka

| P | Soru | Bağlam |
|---|---|---|
| P1 | **Formal marka taraması (Nice 9/42)** — nihai isim netleşince, o isim için: USPTO/EUIPO/TÜRKPATENT taraması; bot-erişimli olmadığından insan/vekil işi | Tüm vetlemeler registry-düzeyiydi |
| P2 | **Nihai isim kararı** + (ancak karar sonrası) namespace rezervasyonu — TABOS kod adıdır, rezervasyon bilinçli ertelendi; not: bakir alanların yarı ömrü kısa (agnix 0→267⭐ ~1 yılda), isim netleşince hızlı davranılmalı | Arda (2026-06-06): "kod adı gibi düşün" |
| P1 | Nihai isim için büyük-motor (Google/Bing) tam web taraması — duyurudan önce zorunlu (2. tur dersi: registry/Mojeek düzeyi yetmez); kayıt: `naming-tabos.json` web sütunu NOT SWEPT | [naming-tabos.json](../research/raw/naming-tabos.json) |
| P2 | tabos.org'un mevcut sahibi (Alman FOSS grubu, flathub `org.tabos.*`) ile karışıklık riski düşük ama izlenmeli; tabos.com (1996) sahibi RDAP entity lookup'ı yapılmadı | Naming raporu |

## I. Dil ve Verification

| P | Soru | Bağlam |
|---|---|---|
| ✅ KARAR | **Kernel verification = saf Rust + tiered-assurance** (Tier0 Miri+coding-guidelines zorunlu, Tier1 Kani her unsafe/parser'da, Tier2 Verus seçici: capability invariant'ları). seL4-üstü yolu v1'de DEĞİL; sertifikasyon pazarına girilirse v3 opsiyonu olarak saklı. asm test-covered (formal değil) | Çözüldü 2026-06-07 · [KERNEL-FOUNDATION-SPEC §8](KERNEL-FOUNDATION-SPEC.md) |
| P1 | `no_std` çekirdek bağımlılık tabanının denetimi — Rust std/core henüz doğrulanmadı (AWS girişimi sürüyor, ~7.5k unsafe fonksiyon); kernel hangi minimal crate setine güvenecek? | AWS verify-std girişimi |
| P1 | Native-Rust inference (candle/mistral.rs) tek-node/dense model için C++ engine'i ne zaman tamamen ikame eder — tamamen-Rust node image mümkün mü? | stack-fit bulgusu |
| P2 | Ferrocene qualification'ı (ASIL D) gerçekten gerekli mi — functional-safety/otomotiv pazarına girilecek mi, yoksa FLS+consortium-guidelines yeterli mi? | EU CRA vs ISO 26262 |
| P2 | EU CRA zaman çizelgesi (Eyl 2026 raporlama, Ara 2027 CE) TABOS sürüm planına nasıl oturur — SBOM/provenance hattı ne zaman kurulur? | Reg. (EU) 2024/2847 |

## H. Süreç / Metodoloji

| P | Soru | Bağlam |
|---|---|---|
| P1 | **Persona doğrulaması**: gerçek agent geliştiricileri ve operatörlerle görüşme — [PROCESS §4](PROCESS.md) taslak personaları/JTBD'leri masa başı üretildi, sahada doğrulanmadı (Design Thinking Empathize boşluğu) | G0 gate kriteri |
| P2 | Success-measure izleme otomasyonu: VISION §7 ölçülerinin gate-bazlı R/Y/G takibi için araç/dosya düzeni (Faz 1'de SUCCESS-MEASURES.md) | [PROCESS §3.4](PROCESS.md) |

---

**Sayım (2026-06-07):** Açık: P0 ×7 · P1 ×29 · P2 ×19 — toplam 55. **Çözülen kararlar:** substrat (Firecracker/tek-vCPU/LinuxBoot), kernel-verification (saf-Rust tiered), uygulama dili (Rust). 1 madde validation-gate'e dönüştü (<50 ms spawn). P0'lar kapanmadan spec donması ilan edilmez. P0'lar kapanmadan spec donması ilan edilmez ([VISION §8 Faz 0](VISION.md)).
