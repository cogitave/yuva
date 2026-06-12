# Yuva L2 Residual Assumptions — the EL2 trusted base the proofs do NOT discharge

> An EXPLICIT assumption set, in the seL4 / SeKVM tradition: a formally-verified
> kernel is only as trustworthy as the things its proofs *assume away*, so those
> things must be written down, not buried. seL4 ships its proofs with a named list
> of what is NOT proven (the boot code, the hand-written assembly, the hardware
> model, and DMA) [1]; SeKVM and its Arm-relaxed-memory follow-on do the same,
> and indeed their headline research contribution is *narrowing* that list one
> assumption at a time [2][3]. This document is Yuva's version of that list for
> the L2 sovereignty rungs that have landed — **L2.0 `el2 OK`** (the EL1↔EL2
> world-switch) and **L2.1 `stage2 OK`** (stage-2 demand-translation, the ARM
> analog of x86 EPT-violation handling). It states, bluntly, what the Yuva
> Kani/Miri proofs DO discharge and what they leave as a residual trusted base
> that only a real Arm board (or a future relaxed-memory proof) can close.
> Companion: [SOVEREIGNTY-L2-ROADMAP.md](SOVEREIGNTY-L2-ROADMAP.md) (the L2 plan)
> · [SOVEREIGNTY-ROADMAP.md](SOVEREIGNTY-ROADMAP.md) (the L0–L3 ladder). It is
> referenced directly from the silicon glue (`arch/aarch64/stage2.rs` cites this
> file as the home of the cache-to-PoC residual assumption).

## 1. What IS proven (the discharged base)

The Yuva verification posture is deliberate and NARROW, following the
pKVM / SeKVM / seL4 / CCA-RMM precedent: prove the *isolation* properties (the
descriptor/syndrome bit-algebra and the rights-subset attenuation), NOT full
functional correctness of the privileged glue. Three machine-checked lanes carry
the load, all on a stock `ubuntu-latest` runner with NO Arm silicon:

- **The stage-2 descriptor & trap-syndrome bit math (Kani, `tb-encode`).** The
  pure, `#![forbid(unsafe_code)]`, host-buildable algebra that `tb-hal`'s
  silicon-unsafe glue CALLS byte-identically — `tb-encode/stage2.rs` (the
  VMSAv8-64 second-stage descriptor + `VTCR_EL2`/`VTTBR_EL2` packers) and
  `tb-encode/el2_trap.rs` (the `ESR_EL2`/`HPFAR_EL2`/`FAR_EL2` decoders) — is
  proven by five L2.1 harnesses in `tb-encode/proofs.rs`: `kani_s2_leaf_wellformed`
  (every leaf carries S2AP=RW + the Access Flag + the correct block/page low bits,
  address preserved), `kani_s2_table_and_vttbr` (the VMID packs into `[63:48]`
  bit-disjoint from the `[47:12]` BADDR — no VMID can corrupt the root address),
  `kani_vtcr_wellformed` (each field lands in its own slice with RES1 bit[31] set
  — the SL0/T0SZ off-by-one walk-length bug class is fenced), `kani_esr_decode_total`
  (EC/DFSC/WnR/S1PTW decode total over ALL 64-bit syndromes; the translation-fault
  classifier is exact against an independent re-derivation), and
  `kani_hpfar_fault_ipa` (the faulting IPA is page-aligned for every input and in
  range over the reachable HPFAR domain). L2.2 adds ONE more —
  `kani_exit_classifier_total` (the total `ESR_EL2.EC` exit-dispatch table
  `classify_exit`: the six MUST ECs map to their named arms and EVERY other EC
  maps to the fail-closed `Undef`/inject-UNDEF default, the
  `arm_exit_handlers[0..EC_MAX]=kvm_handle_unknown_ec` discipline machine-checked,
  plus the injected-UNDEF syndrome encoder `esr_inject_undef`). L2.3 adds TWO more
  — `kani_sysreg_iss_decode_total` and `kani_dabt_iss_decode_total` (the SYS64
  MSR/MRS ISS decoders and the Data-Abort MMIO ISS decoders, each TOTAL over every
  64-bit `ESR` AND round-trip-correct against an independent literal-Arm-ARM-shift
  reference, the trap-and-emulate decode the aL2.3 handler classifies sysreg/MMIO
  accesses with). aL2.4 adds ONE more — `kani_sctlr_el1_guest_enable` (the guest's
  `SCTLR_EL1` first-stage ENABLE word: `sctlr_el1_guest_enable(baseline)` OR-sets
  EXACTLY bits {0,2,12} = `M|C|I`, preserves every other baseline bit, and is
  idempotent — the load-bearing "S1-after-S2" step the aL2.4 guest runs to bring
  its first stage up UNDER our second stage, pinned to a machine-checked invariant
  rather than a hand-written asm immediate). aL2.5 adds ONE more —
  `kani_gich_lr_encode_roundtrip` (the GICv2 `GICH_LRn` list-register encoder:
  `gich_lr_encode(vintid,pintid,state,priority,group,hw,eoi)` packs each field into
  its documented slice — round-trip-recovered via INDEPENDENT literal Arm-ARM
  shifts — with NO bit set outside the QEMU `GICH_LR_MASK` and the bit-19
  PhysicalID/EOI mux honored, the pure value the EL2 monitor stores into `GICH_LR0`
  to SOFTWARE-INJECT a virtual interrupt, pinned so a field-bleed typo in the
  injected LR is a proof failure not a silently-dropped vIRQ). aL2.6 adds THREE
  more — `kani_ste_s2_roundtrip` (the stage-2-only SMMUv3 STE: `Config==0b110`,
  every `S2VMID`/`VTCR`/`S2TTB` field round-trip-recovered via INDEPENDENT shifts
  with no bit bleed, the stage-2-only dwords zero), `kani_ste_vtcr_matches_cpu_
  stage2` (THE LEMMA: the STE `VTCR` projection is BIT-IDENTICAL to `VTCR_EL2[18:0]`
  — the SMMU stage-2 geometry IS the CPU stage-2 geometry), and
  `kani_smmu_cmd_encode_total` (`CFGI_STE`/`TLBI_S12_VMALL`/`CMD_SYNC` place the
  right opcode + operands for all inputs). The `prove-encode` CI lane fails closed
  on a pinned **`EXPECTED_HARNESSES = 28`** (the 15 pre-L2.1 harnesses + the 5
  L2.1 lemmas + the 1 L2.2 classifier lemma + the 2 L2.3 ISS-decoder lemmas + the
  1 aL2.4 SCTLR-enable lemma + the 1 aL2.5 GICH_LR encoder lemma + the 3 aL2.6
  SMMUv3 STE/command-queue lemmas), so a silently deleted, renamed, or vacuous
  harness reddens the lane.

- **The aL2.5 vGIC injection glue + the IMO/TWI window + the GICH/GICV MMIO
  (silicon-unsafe, OUTSIDE the proof boundary).** The
  `tb-hal/arch/aarch64/{el2,el2vgic,el2_vgic_vectors}.rs` glue that arms the vGIC
  window (`msr HCR_EL2 = RW|IMO|TWI`, so the GIC virtual interface's VIRQ line
  reaches EL1 AND the guest's `WFI` traps), enables the virtual CPU interface
  (`GICH_HCR.En`), SOFTWARE-INJECTS a pending virtual interrupt by storing
  `gich_lr_encode(...)` into the `GICH_LR0` MMIO register (`0x0803_0100`), resumes
  the guest past the trapped `WFI` (`ELR_EL2 += 4`), and confirms completion by
  reading `GICH_ELRSR0` (LR0 went empty) — is silicon-unsafe and outside the proof
  boundary. The PURE value computation (the GICH_LRn field packing) IS inside the
  boundary: `tb_encode::el2_trap::gich_lr_encode` is `#![forbid(unsafe_code)]` and
  Kani-proven (`kani_gich_lr_encode_roundtrip` — field round-trip via independent
  literal shifts, no-field-bleed against the QEMU `GICH_LR_MASK`, mirroring
  `gic_internal.h` `REG32(GICH_LR0,0x100)` byte-for-byte including the bit-19
  PhysicalID/EOI mux), so the silicon `write_volatile` next to the just-computed
  value is byte-identical to the proven leaf. The glue is exercised end-to-end by
  the `L2.5: vgic OK` boot self-test, fail-closed (family `0x0761_*`): the verdict
  requires the CONJUNCTION of the guest magic `0x761` (the guest's EL1 IRQ handler
  fired, read `GICV_IAR` == the injected vINTID, set the sentinel, wrote
  `GICV_EOIR`) AND the monitor-side independent confirmation (the `WFI` park was
  observed AND `GICH_ELRSR0` shows LR0 retired — a fact the guest cannot fake by
  writing a magic). **NEW RESIDUAL ASSUMPTION (the I-unmasked window):** unlike
  every other rung (which erets the guest with `SPSR = 0x3C5`, PSTATE.I MASKED),
  aL2.5 MUST eret with `SPSR = 0x345` (PSTATE.I UNMASKED) so the injected VIRQ is
  actually taken — a copy-paste of `0x3C5` would silently never deliver it and the
  guest would re-park forever. This is pinned by a `const _: () = assert!(...)`
  that the I bit (SPSR bit 7) is clear, so a typo is a build error, not a 90s
  timeout. Teardown-first discipline (the L2.1 rule, here load-bearing): `hvc #11`
  clears `HCR_EL2` to the boot baseline (RW only — TWI/IMO off, else the kernel's
  own `halt()` `WFI` would trap to EL2 outside any window, an instant regression)
  and `GICH_HCR.En=0` + zeroes `GICH_LR0` (no stale vIRQ leaks) as its FIRST
  action, before the verdict + unwind; the marker discipline catches a miss
  (`M19: virtio OK` must still print after `L2.5: vgic OK`). MMIO-ordering caveat
  (carried from aL2.1/aL2.3): the EL2 GICH writes run with `SCTLR_EL2.M=0`
  (Device/non-cacheable, correct for MMIO) with a `dsb ish` + `isb` between the
  `GICH_LR0` store and the `eret` so the GIC virtualization hardware observes the
  pending LR before the guest runs (reusing `stage2.rs`'s `dsb_ish_pub`/`isb_pub`).
  Feasibility note: QEMU's GICv2 virt CPU-interface + `gic_update_virt` LR
  injection is byte-identical between v6.2.0 (the dev host) and v8.2.2 (the CI
  runner) and the self-test is CI-green under pure TCG in BOTH (verified locally
  under qemu-6.2 AND under qemu-8.2.2 in Docker).

- **The aL2.4 nested-guest glue + the EL1-side teardown (silicon-unsafe, OUTSIDE
  the proof boundary; a GENUINELY-NEW teardown surface vs aL2.0..aL2.3).** The
  `tb-hal/arch/aarch64/{el2,el2_nested_vectors,stage2}.rs` glue that arms the
  GiB0+GiB1 identity stage-2 (`HCR_EL2.VM=1`), erets into a minimal guest that
  BUILDS + ENABLES its OWN stage-1 (reusing the proven `make_entry`/`level_index`
  encoders + the byte-for-byte mmu.rs MAIR/TCR geometry, locked by const-asserts),
  performs a GENUINE two-stage store/load through a VA with no flat meaning, and
  takes its OWN EL1 `brk` exception, is silicon-unsafe and outside the proof
  boundary — exercised end-to-end by the `L2.4: el2-guest OK` boot self-test
  (the guest magic `0x2E5` requires BOTH the two-stage readback AND the EL1 trap,
  with an INDEPENDENT EL2-side identity-alias readback the guest cannot fake;
  fail-closed family `0x02E5_*`). **NEW RESIDUAL ASSUMPTION:** unlike aL2.0..aL2.3
  (where the guest never touched EL1 sysregs), the aL2.4 guest MUTATES its OWN
  `TTBR0_EL1`/`TCR_EL1`/`MAIR_EL1`/`SCTLR_EL1`/`VBAR_EL1`. The facade SAVES these
  five sysregs before `hvc #8` and RESTORES them after the round-trip (plus an
  `isb` + local `TLBI VMALLE1`/`IC IALLU`), so the kernel resumes on its OWN
  stage-1 with no stale guest translation surviving — the EL1-side teardown, the
  one genuinely-new teardown step. The marker discipline catches a miss: `M19:
  virtio OK` must still print AFTER `L2.4: el2-guest OK` (proving clean kernel
  resume, the same teardown-proof aL2.1 uses). Cache-coherency caveat (carried
  from aL2.0/aL2.1): the EL2-side identity-alias readback (EL2 `SCTLR_EL2.M=0`,
  non-cacheable) reads RAM the guest wrote cacheable; coherent under TCG (no cache
  model), and the load-bearing verdict is the GUEST's own readback (x0=0x2E5), with
  the EL2 alias readback as secondary corroboration only.

- **The L2.3 trap-and-emulate glue (silicon-unsafe, OUTSIDE the proof boundary).**
  The `tb-hal/arch/aarch64/{el2mmio,el2,stage2}.rs` glue that arms the trap window
  (`msr HCR_EL2 = RW|VM|TVM`), decodes a trapped sysreg WRITE / MMIO LDR-STR via
  the proven ISS decoders, routes the MMIO access through the `device_mmio`
  callback SEAM (the split-VMM EXIT-UPCALL point), and ADVANCES `ELR_EL2 += 4` past
  each trapped instruction (`kvm_incr_pc`/`kvm_handle_mmio_return`, the OPPOSITE of
  the L2.1 demand-retry) is silicon-unsafe and outside the proof boundary — it is
  exercised end-to-end by the `L2.3: el2-trap OK` boot self-test (all three arms
  must fire and the values round-trip), fail-closed (ISV=0 aborts -> `FAIL_MMIO_NISV`).

- **The L2.2 exit-dispatch glue (silicon-unsafe, OUTSIDE the proof boundary).**
  The `tb-hal/arch/aarch64/{exits,exits_vectors,el2}.rs` glue that arms the exit
  window (`msr HCR_EL2.TWI|TWE` + `msr CPTR_EL2.TFP`), resumes a trapped `WFx`
  (`ELR_EL2 += 4`, the `kvm_incr_pc`), and SOFTWARE-SYNTHESIZES an EL1
  Undefined-Instruction exception (`msr ESR_EL1/ELR_EL1/SPSR_EL1`, redirect
  `ELR_EL2` to `VBAR_EL1 + 0x200` — the Current-EL-SPx Synchronous slot, NOT the
  Lower-EL `+0x400`, exactly `enter_exception64`'s `mode == target_mode`) carries
  three residual obligations. (1) COHERENCY — the served-mask cells are
  EL2-only (`SCTLR_EL2.M=0`, non-cacheable) and the VERDICT leaves via the x0
  register channel, never an EL1-read cacheable static, so the same
  EL2(MMU-off)/EL1(Normal-WB) coherency caveat L2.0/L2.1 carry applies and is
  mitigated identically; on real silicon the injected-exception path would
  additionally need cache cleans the TCG no-cache model elides. (2) FP-TRAP
  PRIORITY — the default-arm trigger (EC `0x07`) only reaches the `CPTR_EL2.TFP`
  EL2 trap because the facade opens `CPACR_EL1.FPEN=0b11` for the window (else a
  lower-EL FP trap to EL1 would win), and the trigger is emitted via
  `.inst 0x1e2703e0` (`fmov s0, wzr`) so the softfloat `-fp-armv8,-neon`
  assembler gate does not reject it. (3) TEARDOWN — the done HVC restores
  `HCR_EL2`/`CPTR_EL2` to the boot baseline as its FIRST action, so the kernel's
  own later `wfi` (in `halt()`) and any FP use never trap outside the window
  (zero regression). Sound under TCG now because QEMU A-profile TCG honors
  `HCR_EL2.TWI/TWE` and `CPTR_EL2.TFP` and the inject reduces to a plain
  EL2→EL1 `eret`-to-a-computed-PC (the L2.0/L2.1 primitive); a glue bug surfaces
  as `L2.2: el2-exits OK` MISSING (a red marker), never a false green.

- **The rights-subset / attenuation induction (Kani, `tb-caps-core`).** The
  pKVM-style "stage-2 only ever maps frames the guest owns or has been granted"
  property is NOT a new proof obligation — it reduces to the no-confused-deputy
  invariant Yuva already machine-proves at M11: `Rights::intersect` is bitwise-AND,
  so every derived capability is a subset of its parent, and
  `kani_step_preserves_attenuation` shows a single capability-space step preserves
  that subset relation inductively. The `prove-caps` lane pins
  **`EXPECTED_HARNESSES = 12`**. When a guest stage-2 leaf is keyed on a capability
  handle (the later rungs), "the leaf maps an owned/shared frame" becomes an
  instance of this already-proven law.

- **UB-freedom (Miri).** The T0 gate runs Miri over `tb-caps-core` + `tb-encode`,
  so the pure algebra is proven free of undefined behaviour (no overflow, no OOB,
  no uninitialised read) on the SAME code the silicon glue calls — zero model
  drift between "what Kani proved" and "what the kernel computes."

- **The framekernel invariant.** The `kernel` crate and the `caps/mem/ipc/blocks/infer`
  crates are `#![forbid(unsafe_code)]`; EVERY privileged `msr`/`mrs`, `write_volatile`
  descriptor splice, naked world-switch, and `TLBI` is confined to
  `tb-hal/arch/aarch64/{stage2,el2,el2_vectors,boot}.rs` behind the safe
  `stage2_selftest() -> Stage2Proof` / `el2_selftest() -> El2Proof` facades. The
  kernel only ever branches on a closed enum (`Stage2Proof::{Proven{fault_ipa},
  Faulted{code}, Unavailable, NotApplicable}`).

**What this proves, precisely:** the descriptor/ESR/HPFAR *bit transforms* are
correct and total, the capability *attenuation* is monotone, and the pure layer
is UB-free. **What it does NOT prove:** that the hardware, executing the
hand-written assembly under a weak memory model with real caches and TLBs, *does
what the bit math assumes*. That gap is the residual TCB enumerated below — and,
exactly as in the precedents, it is the silicon glue (`stage2.rs`/`el2.rs`), not
the proven algebra, that carries it.

## 2. The residual EL2 trusted base (assumptions A1–A6)

Each assumption states (a) WHAT is assumed, (b) WHY it is currently sound under
the QEMU-TCG CI substrate, and (c) the PATH to narrowing it.

### A1. aarch64 relaxed-memory ordering of the barrier / TLBI sequences

**Assumed.** That the explicit `dsb ishst; isb` table-publish dance (mirrored
from `mmu.rs`), the `dsb ish; isb` after each `TLBI`, and the `isb` after every
`msr VTCR_EL2/VTTBR_EL2/HCR_EL2` are SUFFICIENT to order, on a weakly-ordered
multiprocessor Arm core, (i) the EL1 builder's stage-2 descriptor stores against
(ii) the hardware stage-2 walker's and the EL2 abort handler's subsequent reads,
and (iii) the `HCR_EL2.VM=1` arm against the first stage-2-translated guest
access. The architectural rules for these sequences live in the Arm ARM
(DDI 0487) D-section on barriers, TLB maintenance, and stage-2 Break-Before-Make
[4]; Yuva encodes them by hand in the glue.

**Sound under TCG now because** QEMU's TCG is a sequentially-stronger executor
than real silicon and models no store buffer, no out-of-order completion, and no
cache hierarchy [5], so the round-trip closes (`Stage2Proof::Proven`) even where
a barrier is technically under-strength for a real core. The L2.1 smoke also only
ever writes INVALID→valid leaves (a first map), and the architecture does not
cache invalid entries — so the demand path needs no `TLBI` for correctness on the
happy path; the `TLBI IPAS2E1IS` it issues is "for silicon parity," not for the
TCG pass. Live valid→valid remaps (which WOULD require Break-Before-Make) are not
exercised by the single-guest smoke.

**Path to narrowing.** (1) Run the same `L2.1: stage2 OK` round-trip on a real
weakly-ordered Arm board (a multi-core SMP guest stresses the ordering TCG hides).
(2) Adopt the SeKVM Arm-relaxed-memory model [3] as the proof vehicle: it
formalizes exactly this question — that a hypervisor's page-table + TLB + barrier
sequences preserve isolation under the Arm relaxed-memory architecture — and is
the canonical assumption-narrowing precedent for this rung. Until then A1 is an
honest, documented gap, not a verified property.

### A2. Stage-2 TLBI + cache-to-PoC maintenance with EL2 `SCTLR_EL2.M=0`

**Assumed.** That the stage-2 TLB-invalidation family — `TLBI IPAS2E1IS` (one IPA,
by VMID, inner-shareable) on a demand map and `TLBI VMALLS12E1IS` (all stage-1&2
for the VMID) on arm/disarm — together with cache maintenance, correctly publish
the EL1-built tables to the EL2 walker DESPITE the EL2 abort handler running with
`SCTLR_EL2.M=0` (MMU off → its accesses are Device/non-cacheable and flat-mapped),
while EL1 maps the SAME RAM Normal-WB cacheable. This is a genuine aliasing hazard:
EL2 reads, MMU-off and non-cacheable, the very stage-2 descriptors EL1 wrote
cacheable.

**Sound under TCG now because** TCG models no caches at all, so the EL2 walker and
handler observe the EL1 stores immediately with only the `dsb ishst; isb` the
builder issues [5]. Yuva also sidesteps the hazard structurally: the result of
the round-trip is delivered EL2→EL1 in a register (`x0`), never read back by EL1
from EL2-mapped memory; the EL2 self-context cells (`S2_CTX`) are a 64-byte-aligned
single-accessor region the EL1 kernel never touches; and `BOOTED_AT_EL2` is the
one cross-EL cacheable static, written caches-off at boot.

**Path to narrowing.** On real silicon the EL1 builder must additionally CLEAN the
stage-2 table frames to the Point of Coherency (a `dc cvac`/PoC sweep) before the
MMU-off EL2 walker reads them — the residual step the glue documents in
`arch/aarch64/stage2.rs` and points here. Narrowing = (1) add the PoC clean and
validate on a real core with caches enabled; (2) bring the EL2 monitor up with its
own MMU + cacheable stage-2 mappings so the EL1/EL2 attribute mismatch disappears.
This is the same residual L2.0 already carries for its shared monitor state.

### A3. SMMU / IOMMU DMA-confinement (the silicon-gated half of aL2.6)

**Partly discharged (table-programming), residual narrowed.** The L2.1 CPU-side
stage-2 confines every EL1&0 *CPU* access (including the guest's own stage-1
walk), but a DMA-capable device bypasses the CPU MMU and stage-2 entirely — so a
passed-through device's DMA could read or write all of Yuva+agent memory. Rung
**aL2.6 `smmu OK`** now discharges the *table-programming* half of this obligation:
the EL1 kernel probes `SMMU_IDR0.S2P`, builds a 1-entry linear stream table + one
**stage-2-only** Stream Table Entry (`Config==0b110`) whose `S2TTB`/`S2VMID`/`VTCR`
point at the **SAME** stage-2 L1 root the CPU uses (the STE `VTCR` is the
Kani-proven bit-projection of the CPU's `VTCR_EL2` — `tb_encode::smmuv3::
ste_vtcr_from_vtcr_el2`, so the SMMU stage-2 tables ARE the CPU stage-2 tables),
programs `STRTAB_BASE`/`CMDQ_BASE`/`EVENTQ_BASE`/`CR0`, pushes
`CMD_CFGI_STE`+`CMD_SYNC`, and observes the SYNC drain with `GERROR` clean and no
`C_BAD_STE` event — i.e. **the SMMU ACCEPTED the well-formed stage-2 STE**.

**What aL2.6 PROVES vs what it does NOT.** The marker `L2.6: smmu OK` asserts
ONLY *"the stage-2 STE is well-formed AND the SMMU accepted it (CFGI_STE synced,
no GERROR/C_BAD_STE)"* — the IOMMU twin of `L2.1 stage2 OK`. It does **NOT** assert
the actual DMA-isolation *guarantee*: that a rogue/buggy physical device is
**BLOCKED** from reaching memory outside its grant. **That needs REAL SILICON**
(the §6 two-tier-test hole, the same residual the x86 VT-d/L2.8 path carries): QEMU
emulation cannot prove isolation against silicon errata, ATS/PRI corner cases,
peer-to-peer DMA bypass, or a non-ACS-clean topology. Under pure TCG there is no
real DMA engine to confine, no bus-mastering races, no IMPLEMENTATION-DEFINED SMMU
behavior — so emulation proves the **programming is well-formed and ACCEPTED**,
never that silicon enforces it. The pKVM/AVF security model makes the same scoping
explicit — stage-2 confidentiality+integrity is enforced by the EL2/owner-owned
tables, with the silicon DMA-confinement guarantee a separate obligation [6].

**QEMU-version note (the Proven vs skip gate).** Stage-2 SMMUv3 support (the
Mostafa series) landed in **QEMU 9.0** (2024), NOT 8.1. So on a QEMU that
advertises `IDR0.S2P==1` (>= 9.0, verified Proven end-to-end here under
**qemu-10.0.8**: the STE is accepted, `smmu: stage-2 STE accepted` + `L2.6: smmu
OK` print) the table-programming proof runs for real under TCG. On the current CI
image (`tabos-qemu8` = QEMU 8.2.2) and local qemu-6.2 the SMMU advertises `S1P=1`
but `S2P=0`, so the kernel's `IDR0.S2P` gate takes the **honest GREEN skip**
(`L2.6: smmu OK (no stage-2 SMMU, skipped)`) — NO stage-2 STE is written to an
S1-only SMMU. The pure STE/command encoders remain Kani-proven on the host runner
regardless of the QEMU version (the `prove-encode` lane). When the CI QEMU is
bumped to >= 9.0 the Proven path runs in CI with **zero kernel change**.

**Path to fully narrowing.** The full DMA-isolation guarantee (and the optional
behind-SMMU `virtio-*-pci` DMA-translated-through-our-stage-2 observation, a
PCIe-only stretch arm not wired in the core proof) needs a real, ACS-clean board —
emulation cannot prove isolation (the two-tier test hole the roadmap §6 flags).
Roadmap rung **L2.8** is the x86 VT-d sibling of this same split.

### A4. Secure-boot of the EL2 image

**Assumed.** That the EL2 monitor image that `boot.rs::_start` installs (the
resident nVHE monitor at `VBAR_EL2`, `HCR_EL2.RW`, `SCTLR_EL2=0x30C50830`) is the
authentic, unmodified Yuva binary. The proofs reason about the *source* of the
monitor; they assume the bytes actually executing at EL2 are that source, loaded
by a trustworthy boot chain. Today QEMU loads the kernel image directly — there is
no signature check, no measured boot, no chain of trust below the monitor.

**Sound under TCG now because** CI builds the image and immediately runs it in the
same hermetic job — the loaded bytes ARE the just-built bytes, so the assumption
holds by construction in the test harness (there is no untrusted firmware in the
loop to subvert it).

**Path to narrowing.** A real deployment must (1) verify the EL2 image against a
hardware root of trust (Arm Trusted Firmware / a signed-boot or measured-boot
chain) before transferring to EL2, and (2) account for the firmware floor below
EL2 (EL3/Secure-EL2, the SoC boot ROM) which Yuva does NOT and cannot verify —
sovereignty at EL2 is always RELATIVE to that floor, exactly as the x86 track is
relative to SMM/ME. This mirrors seL4's explicit "the initial boot loader is
trusted" assumption [1] and CCA's reliance on a measured-boot RMM launch [7].

### A5. The assembly / naked world-switch + the QEMU machine interface

**Assumed.** The seL4 line, verbatim for Yuva: *the hand-written assembly and the
hardware are an assumption* [1]. Specifically — (i) the `#[unsafe(naked)]`
world-switch and abort-retry stubs (`el2.rs`, `el2_vectors.rs`), which save/restore
the 0x110-byte exception frame, program `ELR_EL2`/`SPSR_EL2`, and `eret`, are
trusted to match the EL2 vector layout (the Kani proofs cover the *decoders* the
handler calls, NOT the GPR save/restore sequence); (ii) the four HVC immediates
that bracket the windows — `HVC #0`/`#1` (L2.0 bootstrap/done) and `HVC #2`/`#3`
(L2.1 arm / done+teardown, with teardown as the FIRST action on the done branch
because returning to EL1 with `HCR_EL2.VM=1` still set instantly aborts the kernel)
— are trusted to dispatch correctly; and (iii) the QEMU `virt,virtualization=on,
gic-version=2 -cpu cortex-a72` machine interface is trusted to faithfully model the
A-profile EL2/stage-2 architecture [4][8] — its `target/arm` stage-2 walk and its
`HPFAR_EL2`/`ESR_EL2` syndrome latching ARE the silicon, for CI purposes.

**Sound under TCG now because** the round-trip is end-to-end behavioural: a real
world-switch or frame-layout bug surfaces as `L2.1: stage2 OK` MISSING (a red
marker, no faked OK) — `Stage2Proof::Faulted{code}` is rendered WITHOUT the
`stage2 OK` substring so the run-script grep stays fail-closed. The const-asserts
(`size_of::<Frame>() == 0x110`, the offset checks, the EC-constant locks against
the proven `tb_encode::el2_trap` values) catch layout drift at build time.

**Path to narrowing.** The asm is irreducibly trusted (as in every verified
hypervisor); the best available narrowing is (1) keep it minimal and const-asserted,
(2) re-run on real hardware so the machine-interface assumption is discharged
against actual silicon rather than TCG, and (3) — for the longer term — translation
validation of the compiled stubs, in the seL4 binary-verification spirit.

### A6. The verification-to-binary gap (source, not the compiled image)

**Assumed.** The Kani harnesses prove the Rust *source*/MIR of `tb-encode`; the
proofs therefore trust `rustc` + LLVM to compile that source faithfully, and trust
that the bits `tb-hal` links are the bits Kani checked. seL4 closes this with
translation validation down to the binary [1]; Spoq (proofs that hold for the
*compiled* binary) [9] and CN (separation-logic refinement types verifying the real
pKVM C) [10] are the precedents for shrinking it.

**Sound under TCG now because** `tb-encode` is the SAME crate, compiled by the SAME
toolchain, that both Kani verifies and `tb-hal` calls — there is no hand-transcribed
second copy of the bit math to drift, which removes the largest practical source of
spec/impl divergence even without binary-level proof.

**Path to narrowing.** Adopt a binary-level or translation-validated proof flow
(the Spoq/seL4 approach) once the encoder surface stabilizes; until then the
compiler and linker are part of the trusted base, stated here so they are not
mistaken for verified.

## 3. How the precedents treat each assumption

| Assumption | seL4 [1] | SeKVM / Arm-RM [2][3] | pKVM / AVF [6] | CCA-RMM [7] | CN [10] |
|---|---|---|---|---|---|
| A1 relaxed memory | assumed (sequential model) | **NARROWED** — proven under Arm RM | assumed | partly modelled | n/a |
| A2 TLBI / cache | assumed | reasoned in the RM proof | assumed | assumed | n/a |
| A3 DMA / IOMMU | **assumed (explicit)** | out of scope | separate obligation | assumed | n/a |
| A4 secure boot | **assumed (boot loader trusted)** | assumed | measured launch | measured RMM | n/a |
| A5 asm + hardware | **assumed (explicit)** | assumed | assumed | assumed | assumed |
| A6 source→binary | closed (binary verification) | Spoq closes it [9] | C, not binary | Coq, source | **closes the buddy allocator** |

Yuva sits where pKVM/CCA sit today: the *isolation bit-algebra* and *attenuation*
are machine-proven, the relaxed-memory / TLBI / DMA / boot / asm base is honestly
assumed, and the published narrowing path is "a real board + the SeKVM relaxed-memory
model." The deliberate Yuva divergence from pKVM (documented in the roadmap): Yuva
RETAINS sovereign scheduling inside the trusted core, so availability/DoS is
explicitly scoped OUT of the proven set while memory isolation stays in it.

## 3a. M30 external-dependency entries (the inference-transport trust path)

- **QEMU virtio-console device model — status ACCEPTED-PERMANENT** (M30 proposal
  §9, option A): the M30 chardev-harness lanes route the verified inference
  transport through stock QEMU's `virtio-serial-device` + `virtconsole` device
  model on BOTH arches, so that model is part of the `M30: infer-transport OK`
  trust path alongside QEMU itself (already a trust-path member for every lane).
  Accepted because console (DeviceID 3) is the ONLY class with a stock-QEMU
  virtio-mmio peer on both arches — zero QEMU patching, the decisive §3 coupling.
  The parity successors if this dependency is ever to be retired: a custom QEMU
  device / vhost-user (revisit at B2) / an aarch64 tb-vmm. The x86/KVM lane's
  stage-C tb-vmm backend (`transport=TB-VMM-HOST`) replaces it on that lane only.
- **Symmetric host-echo key — named residual** (M30 proposal §12): the M30 echo
  key K is symmetric and revealed in cleartext on the channel, so the echo
  proves host PARTICIPATION (per-run OS-RNG custody + the cross-process guard
  equality), never host EXCLUSIVITY — an adversarial host is out of scope (the
  host is trusted ground), and the upgrade to exclusivity is the M33 signature
  primitive, tracked, not claimed.

## 4. Status & review discipline

These assumptions are LIVE and shrink as rungs land: A3 closes at L2.8 (SMMUv3),
A1/A2 narrow when the round-trip first runs on real Arm silicon, and A4/A6 narrow
with a measured-boot chain and a binary-level proof flow. Any new privileged glue
MUST either be covered by a `tb-encode` Kani lemma (extending `EXPECTED_HARNESSES`
in lockstep) or be added here as a named residual assumption — a new `unsafe` block
in `tb-hal/arch/aarch64` with no entry in this file is a review failure. This is the
seL4 contract: the proof is only as honest as the assumption list it ships with.

## 5. Citations (real sources only)

1. Klein, Elphinstone, Heiser, et al. **seL4: Formal Verification of an OS Kernel.**
   SOSP 2009; seL4 Foundation Verification pages + whitepaper (Isabelle/HOL to
   binary; the explicit assumption set — boot code, assembly, hardware, DMA).
   <https://sel4.systems/Verification/proofs.html>
2. Li, Li, Gu, Nieh, Hui. **A Secure and Formally Verified Linux KVM Hypervisor
   (SeKVM / microverification).** IEEE S&P 2021.
   <https://www.cs.columbia.edu/~nieh/pubs/>
3. Tao, Yao, Li, Li, Nieh, Gu. **Formal Verification of a Multiprocessor Hypervisor
   on Arm Relaxed Memory Hardware.** ACM SOSP 2021 (the relaxed-memory
   assumption-narrowing model). <https://www.cs.columbia.edu/~nieh/pubs/>
4. Arm Ltd. **Arm Architecture Reference Manual for A-profile (DDI 0487)** —
   VMSAv8-64 stage-2 translation, VTCR_EL2/VTTBR_EL2, ESR_EL2/HPFAR_EL2, TLB
   maintenance + stage-2 Break-Before-Make.
   <https://developer.arm.com/documentation/ddi0487/latest>
5. QEMU project. **A-profile CPU architecture support / TCG emulated features**
   (FEAT_AA64EL2, FEAT_VMID16, FEAT_S2FWB, FEAT_XNX, FEAT_TGran*; no cache/relaxed-
   memory model). <https://www.qemu.org/docs/master/system/arm/emulation.html>
6. Android Open Source Project. **Android Virtualization Framework / pKVM Security
   Model** (stage-2 confidentiality+integrity enforced by the EL2-owned tables;
   availability scoped OUT). <https://source.android.com/docs/core/virtualization/security>
   · J. Edge (LWN), **KVM for Android** — Will Deacon, KVM Forum 2020 (nVHE EL2,
   one-way host deprivileging, fixed hypercall set). <https://lwn.net/Articles/836693/>
7. Li, Li, Dall, Gu, Nieh, Sait, Stockwell. **Design and Verification of the Arm
   Confidential Compute Architecture (Realms / RMM, Coq).** USENIX OSDI 2022.
   <https://www.usenix.org/conference/osdi22/presentation/li>
8. QEMU project. **'virt' generic virtual platform** (machine option
   `virtualization=on`, `gic-version`, cortex-a72).
   <https://www.qemu.org/docs/master/system/arm/virt.html>
9. Li, Li, Qiang, Gu, Nieh. **Spoq: Scaling Machine-Checkable Systems Verification
   in Coq** (LLVM→Coq; proofs hold for the compiled binary). USENIX OSDI 2023.
   <https://www.usenix.org/conference/osdi23/presentation/li-xupeng>
10. Pulte, Makwana, T. Sewell, Memarian, P. Sewell, Krishnaswami. **CN: Verifying
    Systems C Code with Separation-Logic Refinement Types** (verifies Google
    pKVM's buddy allocator). POPL 2023. <https://www.cl.cam.ac.uk/~cp526/popl23.html>
