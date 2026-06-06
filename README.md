# TABOS

**Türkiye's Agent Based Operating System** — AI agent'ların birinci sınıf vatandaş olduğu, sıfırdan tasarlanan işletim sistemi.

> Faz: **0 — Planlama** (yalnızca dökümantasyon; kod yok) · Başlangıç: 2026-06-06
>
> **İsim notu:** "TABOS" bu projenin **kod adıdır** (working title) — nihai marka değildir, değişebilir. İsme bağlı her şey (kernel prefix `tb_`, CLI adları, domain önerileri) placeholder'dır ve hiçbir yerde hardcode edilmez. Nihai isim + rezervasyon kararı: [OPEN-QUESTIONS §G](docs/OPEN-QUESTIONS.md).

## Ne?

TABOS, agent'ın **zihni** (context, memory, in-flight inference) ile **bilgisayarını** (sandbox, dosya sistemi, tool'lar) tek bir kernel nesnesi olarak yöneten; hafızayı, kendini geliştirmeyi ve çoklu-agent yaşamını framework nezaketi değil **işletim sistemi garantisi** olarak sunan, insan-masaüstü mirası taşımayan bir OS tasarımıdır.

- **Sıfırdan kernel/unikernel** — syscall ABI dahil her şey agent'lar için; her alt sistem "agent'a ne kazandırıyor?" sorusuyla yaşar
- **LLM-agnostik** — `model:anthropic/...` ile `model:local/llama` aynı kontratın iki driver'ı
- **Memory-first** — her agent kalıcı, katmanlı, recall-edilebilir memory ile doğar
- **Self-improvement OS servisi** — reflection default-on; skill'ler doğrulanmadan commit olmaz; ölçen, ölçülenden ayrı
- **Tek = çoklu agent** — tek-agent oturumu, N-agent oturumunun |üye|=1 özel hâlidir

## Döküman Haritası

| Döküman | İçerik |
|---|---|
| [docs/RESEARCH-REPORT.md](docs/RESEARCH-REPORT.md) | Kaynakçalı derin araştırma raporu — 26 arXiv makalesi + 20 sistem belgesi; 25 çekirdek iddia çok-oylu adversarial doğrulamalı, 100 alan bulgusu kaynak-okumalı |
| [docs/VISION.md](docs/VISION.md) | Varlık nedeni, beş tasarım ilkesi, boşluk analizi, başarı kriterleri, yol haritası |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Kernel kararı (capability çekirdek + unikernel beden + exokernel ruhu), nesne modeli, namespace, syscall yüzeyi, scheduler, context scheduler, güvenlik |
| [docs/MEMORY-SPEC.md](docs/MEMORY-SPEC.md) | Default memory: T0-T5 tier'ları + blocks, kayıt şeması (bi-temporal), op ABI'si, konsolidasyon, forgetting, çok-agent namespace'leri |
| [docs/AGENTS-SPEC.md](docs/AGENTS-SPEC.md) | Agent process nesnesi, .taf imaj formatı, spawn protokolü, yaşam döngüsü, IPC, kimlik, oturumlar |
| [docs/SELF-IMPROVEMENT-SPEC.md](docs/SELF-IMPROVEMENT-SPEC.md) | Üç Yasa (Endure>Excel>Evolve), frozen kernel, skill tier'ı, sleep-time sınıfı, arşiv evrimi, güvenlik mekaniği |
| [docs/SOVEREIGNTY.md](docs/SOVEREIGNTY.md) | Temiz-sayfa egemenlik: silikon-zorunlu vs Linux-mirası vs TABOS-sahip sınıflandırması; tb-boot/tb-vmm owned VMM kararı; virtio=OASIS; 'eski bug taşımıyoruz' somut defteri (fork/ambient-authority/ioctl/signals/TOCTOU) — adversarial-doğrulamalı |
| [docs/KERNEL-FOUNDATION-SPEC.md](docs/KERNEL-FOUNDATION-SPEC.md) | Kernel foundation + assembly planı (arch bazında, KARAR-çözümlü): tb-hal crate, boot yolu, 13 asm ünitesi (A1-A13), ABI register setleri, MMU asm-vs-Rust sınırı, asm standartları, test gate'leri, 5-milestone WBS (M0-M4) — ultracode takip omurgası |
| [docs/LANGUAGE-AND-STANDARDS.md](docs/LANGUAGE-AND-STANDARDS.md) | Dil kararı (Rust, katman bazlı) + endüstriyel standartlar (NSA/CISA/ONCD/EU CRA, Ferrocene, SLSA/SBOM, fuzzing) — adversarial-doğrulamalı |
| [docs/PROCESS.md](docs/PROCESS.md) | Süreç kaydı + Design Thinking / Success by Design eşlemesi, persona/JTBD, risk register, review gate'leri (G0-G3) |
| [docs/OPEN-QUESTIONS.md](docs/OPEN-QUESTIONS.md) | 53 açık soru, P0/P1/P2 önceliklendirmeli — P0'lar kapanmadan spec donmaz |
| [research/raw/](research/raw/) | Araştırma ham verisi: doğrulama kayıtları + 8 alan bulgusu + isim vetlemeleri (JSON) |

## Durum İşaretleri

Spec dökümanlarında: **[KARAR]** verilmiş karar · **[ÖNERİ]** araştırmadan türetilmiş güçlü öneri (prototiple test edilecek) · **[AÇIK]** OPEN-QUESTIONS'ta takipli.

## Metodoloji Notu

Bu döküman seti, 147 subagent'lık üç araştırma dalgasının (deep-research → verify+expand → naming) ürünüdür ve bağımsız 3-denetçili adversarial review'dan geçirilmiştir. Kanıt iki sınıftır: 25 çekirdek iddia birincil kaynak metnine karşı çok-oylu adversarial doğrulamalı (kayıtlar: `research/raw/verified.json` + `verified-wave1.json`); 8 alandan 100 yapılandırılmış bulgu tek-araştırmacı kaynak-okumalı. İsim, 31 adayın (24+7; 23'ü tam vetlenmiş) vetlemesi sonrası seçilmiştir; TABOS'un kendi vetleme kaydı: `research/raw/naming-tabos.json`.
