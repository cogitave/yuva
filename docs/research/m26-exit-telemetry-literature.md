# M26 literature survey — EL2 exit-telemetry as a verified experience producer

Companion to [`docs/proposals/M26-exit-telemetry.md`](../proposals/M26-exit-telemetry.md). Synthesis of a research-first arxiv/standards pass over the M26 design space, plus a read of the existing substrate (`exp.rs`, `opframe.rs`, `el2_trap.rs`, `prov.rs`) so the first-increment matches the real code discipline (fixed-width injective `canon`, M22 fold reuse, fail-closed totality, no-float). The pass surveyed THREE candidate strands; this doc records why **Strand A (the exit-telemetry producer) ships alone as M26** and the other two are deferred. Where M26 goes beyond a source it is flagged **[BEYOND]**.

---

## The substrate constraints that shaped the design (read first)
1. **The leaf discipline is rigid and load-bearing.** Every `tb-encode` leaf is a fixed-width (or length-prefixed) injective `canon`/`decode` pair, fail-closed-total (returns `0`/`None`, never panics/partial-writes), folded into the M22 chain via `prov::{append, chain_mix, verify_inclusion, head_witness}` **reused verbatim** — `exp.rs` and `opframe.rs` both write *no new fold math*. A new leaf must do the same.
2. **The honesty-token mechanism is the anti-overclaim spine.** `exp` emits `oracle=DECLARED-PROXY-DEFERRED-M24`; `opframe` emits `keyed=0` / `oracle=HUMAN-DEFERRED-M26`. The marker *mechanically cannot* claim more than is proved. M26's token is `signal=OBSERVATIONAL-NONCAUSAL`.
3. **`el2_trap.rs` already gives the ESR_EL2.EC dispatch keys as Kani-proven const decoders** (`EC_WFX=0x01`, `EC_HVC64=0x16`, `EC_SYS64=0x18`, `EC_IABT_LOW=0x20`, `EC_DABT_LOW=0x24`, `esr_is_translation_fault`). M26's exit-class is *already a verified enum* — it needs only **counting**, not inventing.

---

## Arm A (shipped as M26) — exit telemetry as a producer

- **Garfinkel & Rosenblum, "A Virtual Machine Introspection Based Architecture for Intrusion Detection," NDSS 2003.** The foundational VMI paper: the hypervisor is a privileged, isolated vantage point for observing a guest. Grounds "EL2 as an observation point" — but it is *security* introspection, not a learning signal (M26 reuses the vantage, not the IDS).
- **Linux `perf kvm stat` / KVM tracepoints (`/sys/kernel/tracing/events/kvm`) / eBPF KVM-exit tools.** The *direct prior art*: per-exit-reason accounting and **VM-exit handling-time histograms bucketed by exit number**. Production evidence that "demux the exit, bucket a counter/histogram by exit-class" is a sound observability primitive. (LWN 513317; linux-kvm.org Perf_events.) M26 is the **verified, no-float, chained** form of exactly this.
- **Mao, Schwarzkopf, Venkatakrishnan, Meng, Alizadeh, "Learning Scheduling Algorithms for Data Processing Clusters" (Decima), SIGCOMM 2019, arXiv:1810.01963.** The strongest "learn from system traces → resource decisions" exemplar (21%+ JCT improvement). Justifies the *ambition* of an exit-telemetry state-signal — but Decima is deep-RL, float, online, and closes the loop; M26 deliberately does NOT (see the confounding caveat). Cited for the goal, not the method.
- **Cormode & Muthukrishnan, "An Improved Data Stream Summary: The Count-Min Sketch," J. Algorithms 2005.** The canonical bounded, integer, fixed-memory streaming frequency sketch with provable error bounds — a no-float-implementable successor. **[Design choice]** M26 uses a *direct-mapped per-class* histogram instead (the `EC_*` set is small + closed → no hash collisions to bound → counts are *exact* per class), keeping Count-Min as the named successor if the class space opens.
- **OpenTelemetry Exponential Histogram (OTEP-0149; Metrics Data Model).** The modern standard for bounded high-dynamic-range latency aggregation; its **base-2 / log-scale bucket indexing** is the integer-friendly pattern M26 adopts (a `leading_zeros`-based bucket index) *without* the float mapping.
- **Chaudhry et al., "Offline Evaluation under Unobserved Confounding," arXiv:2309.04222** + **Chaney, Stewart, Engelhardt, "How Algorithmic Confounding in Recommendation Systems Increases Homogeneity and Decreases Utility," RecSys 2018.** The pitfall papers: when the logging policy is **learned from the same closed loop**, propensities are confounded and the OPE bias is **non-identifiable and untestable** — the *exact* exogeneity problem the M24 adversary named, restated for an exit stream. **This is why M26 is PRODUCER-ONLY** (`signal=OBSERVATIONAL-NONCAUSAL`): it records + folds telemetry; it does not close any exit→policy→exit loop.

**[BEYOND]** A **Kani-proven, no-float, in-EL2 streaming aggregation folded into a tamper-evident hash chain** is absent from the prior art (`perf kvm`/eBPF are float, unverified, un-chained; Count-Min/OTel are not verified no-panic integer leaves). The novelty is the *combination* over one decidable M22 fold — claimed narrowly (a verified bounded encoder + fold), not a new aggregation algorithm.

---

## Arm B (deferred to M27) — two-VMID sovereign scheduling

- **ARINC 653 (APEX).** The canonical two-level time-partition model (a major frame of fixed windows, temporal isolation between partitions) — the requirements anchor; a two-VMID time-partition is the minimal two-window major frame.
- **Martins, Tavares, Pinto et al., "Bao: A Lightweight Static Partitioning Hypervisor," 2020** + **"Shedding Light on Static Partitioning Hypervisors for Arm-based MCS," arXiv:2303.11186.** The closest architectural analog to the EL2 nVHE monitor: clean-slate, Armv8/RISC-V, thin, leverages ISA virtualization — and notably Bao **has no scheduler**. That is the design fork: M27 adds the *minimal* time-partition scheduler Bao deliberately omits.
- **ARM Generic Timer — `CNTHP_CTL_EL2` / `CNTHP_TVAL_EL2` / `CNTHP_CVAL_EL2` / `CNTHCTL_EL2`** (Arm ARM DDI 0487; Dall, "Arm Timers and Fire," KVM Forum 2018). The exact mechanism: the EL2 physical timer is the sovereign preemption tick. The x86 dual is the **Intel SDM Vol. 3C VMX-preemption timer**.
- **Lyons, McLeod, Almatary, Heiser, "Scheduling-Context Capabilities," EuroSys 2018** + the **seL4 MCS line** (RTCSA 2020). The verified/sound scheduling grounding (capability-authorized CPU time, budget+period) — the model to gesture at, not reimplement.

Deferred because it needs **new EL2 runtime HAL code** (timer arming + VMID switch in the world-switch) + a two-guest QEMU harness — a sovereignty-track milestone with its own anti-hollow burden, not a leaf bolt-on. **[BEYOND]** folding each *scheduling decision* into the verified experience ledger (sovereignty → learning) is the novel bit; the time-partition mechanism is well-trodden.

---

## Arm C (deferred to M28 — the capstone) — operator INBOUND channel (opframe RX + auth)

- **RFC 9334 (RATS) §10 (Freshness).** The exact gap M25 named: TX-only with a self-asserted epoch carries no freshness. The remedies — **nonce** (verifier-generated) vs **epoch-ID** — give RX its freshness anchor (the operator's challenge nonce).
- **Ma & Tsudik (FssAgg, 2008/2009); Schneier & Kelsey (TISSEC 1999).** The forward-secure aggregate MAC line `opframe` already cites for truncation defense — the *cryptographic* successor to the keyless FNV fold (`keyed=0`).
- **RFC 2104 (HMAC).** The honest yardstick: a naive `keyed-FNV` / `key‖msg` is **NOT** a secure MAC (length-extension). M28 must either implement a real keyed hash (`mac=KEYED-CRYPTO`) or state plainly it is a non-cryptographic keyed checksum (`mac=KEYED-NONCRYPTO`).
- **Bäumer, Brinkmann, Schwenk, "Terrapin Attack," arXiv:2312.12422 / USENIX Sec 2024.** The replay/injection lesson for a serial command channel: bind seq into the MAC'd transcript from message zero + bind the channel epoch into the first authenticated byte. `opframe`'s seq-folded-into-`canon` already anticipates this; RX extends it to the *authenticated* setting.
- **Two-person rule / break-glass (dual-custody lineage; SOC2/ISO 27001 emergency-access).** The authorization model for the highest-consequence input the system accepts ("activate the learned policy"): time-bound, dual-authorized, tamper-logged. C is the **capstone** — it delivers the exogenous-oracle command the entire M23→M24→M25 loop was built to receive (Christiano RLHF arXiv:1706.03741; Thomas Seldonian Science 2019).

Deferred because it is a genuinely new crypto-adjacent construction whose `KEYED-NONCRYPTO`-vs-`KEYED-CRYPTO` honesty boundary is the single biggest hollow-marker risk in the roadmap and deserves a dedicated milestone. The CI self-test must use a SIMULATED enrolled key (`oracle=SIMULATED-ENROLLED-KEY`) that proves the auth plumbing but must **NOT** actually flip `KAN_ACTIVE` (that would defeat M24's refusal). **[BEYOND]** composing FssAgg + RATS freshness + dual-custody into a no-float verified-leaf inbound activation channel anchored to a live provenance head is a synthesis in no single source — the construction is novel; its security is *asserted-not-proven* at the `KEYED-NONCRYPTO` tier (the honest frontier).

---

## The split decision — why A alone is M26
| | Reuse | Hard new artifact | Autonomous-CI risk |
|---|---|---|---|
| **A (M26)** | exit classifier (`el2_trap`, proven) + experience fold (`exp`/`prov`) | none (producer-only) | LOW — pure leaf + synthetic-vector self-test |
| **B (M27)** | the EL2 world-switch | new EL2 *runtime* (timer arm + VMID switch) + 2-guest harness | MEDIUM — TCG models CNTHP but the harness is heavier |
| **C (M28)** | the `opframe` TX framing | a *keyed* construction + a security story | HIGH — the most delicate self-grading (must not activate the cell) |

All three feed the **same** `xp_head`, so they should extend `kind::*` tags **sequentially** against a stable, already-proven fold rather than racing three concurrent schema changes against the M23 schema-stability lemma. A establishes the exit→experience producer; **C is the natural capstone**, not the opener — it delivers the activation command the loop was built to receive. Hence: **M26 = A, M27 = B, M28 = C.**
