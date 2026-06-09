# TABOS L2 Residual Assumptions — the EL2 trusted base the proofs do NOT discharge

> An EXPLICIT assumption set, in the seL4 / SeKVM tradition: a formally-verified
> kernel is only as trustworthy as the things its proofs *assume away*, so those
> things must be written down, not buried. seL4 ships its proofs with a named list
> of what is NOT proven (the boot code, the hand-written assembly, the hardware
> model, and DMA) [1]; SeKVM and its Arm-relaxed-memory follow-on do the same,
> and indeed their headline research contribution is *narrowing* that list one
> assumption at a time [2][3]. This document is TABOS's version of that list for
> the L2 sovereignty rungs that have landed — **L2.0 `el2 OK`** (the EL1↔EL2
> world-switch) and **L2.1 `stage2 OK`** (stage-2 demand-translation, the ARM
> analog of x86 EPT-violation handling). It states, bluntly, what the TABOS
> Kani/Miri proofs DO discharge and what they leave as a residual trusted base
> that only a real Arm board (or a future relaxed-memory proof) can close.
> Companion: [SOVEREIGNTY-L2-ROADMAP.md](SOVEREIGNTY-L2-ROADMAP.md) (the L2 plan)
> · [SOVEREIGNTY-ROADMAP.md](SOVEREIGNTY-ROADMAP.md) (the L0–L3 ladder). It is
> referenced directly from the silicon glue (`arch/aarch64/stage2.rs` cites this
> file as the home of the cache-to-PoC residual assumption).

## 1. What IS proven (the discharged base)

The TABOS verification posture is deliberate and NARROW, following the
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
  plus the injected-UNDEF syndrome encoder `esr_inject_undef`). The `prove-encode`
  CI lane fails closed on a pinned **`EXPECTED_HARNESSES = 21`** (the 15 pre-L2.1
  harnesses + the 5 L2.1 lemmas + this 1 L2.2 classifier lemma), so a silently
  deleted, renamed, or vacuous harness reddens the lane.

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
  invariant TABOS already machine-proves at M11: `Rights::intersect` is bitwise-AND,
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
[4]; TABOS encodes them by hand in the glue.

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
builder issues [5]. TABOS also sidesteps the hazard structurally: the result of
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

### A3. SMMU / IOMMU DMA-confinement (a later rung)

**Assumed.** That nothing performs DMA. The L2.1 CPU-side stage-2 confines every
EL1&0 *CPU* access (including the guest's own stage-1 walk), but a DMA-capable
device bypasses the CPU MMU and stage-2 entirely — so a passed-through device's
DMA could read or write all of TABOS+agent memory. The smoke runs device-less, so
this is vacuously satisfied today.

**Sound under TCG now because** the L2.0/L2.1 self-tests pass through no device and
grant no DMA; the IPA space the guest sees is purely CPU-translated. The pKVM/AVF
security model makes the same scoping explicit — stage-2 confidentiality+integrity
is enforced by the EL2-owned tables, with DMA confinement a separate obligation [6].

**Path to narrowing.** This is roadmap rung **L2.8** (SMMUv3 stream/context tables
mirroring each guest's stage-2, from the SAME `tb-encode` second-stage encoder),
gated behind any device passthrough. The architectural-programming half is
CI-testable on emulated SMMUv3; the actual DMA-isolation *guarantee* needs a
real, ACS-clean board — emulation cannot prove isolation (the two-tier test hole
the roadmap §6 already flags).

### A4. Secure-boot of the EL2 image

**Assumed.** That the EL2 monitor image that `boot.rs::_start` installs (the
resident nVHE monitor at `VBAR_EL2`, `HCR_EL2.RW`, `SCTLR_EL2=0x30C50830`) is the
authentic, unmodified TABOS binary. The proofs reason about the *source* of the
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
EL2 (EL3/Secure-EL2, the SoC boot ROM) which TABOS does NOT and cannot verify —
sovereignty at EL2 is always RELATIVE to that floor, exactly as the x86 track is
relative to SMM/ME. This mirrors seL4's explicit "the initial boot loader is
trusted" assumption [1] and CCA's reliance on a measured-boot RMM launch [7].

### A5. The assembly / naked world-switch + the QEMU machine interface

**Assumed.** The seL4 line, verbatim for TABOS: *the hand-written assembly and the
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

TABOS sits where pKVM/CCA sit today: the *isolation bit-algebra* and *attenuation*
are machine-proven, the relaxed-memory / TLBI / DMA / boot / asm base is honestly
assumed, and the published narrowing path is "a real board + the SeKVM relaxed-memory
model." The deliberate TABOS divergence from pKVM (documented in the roadmap): TABOS
RETAINS sovereign scheduling inside the trusted core, so availability/DoS is
explicitly scoped OUT of the proven set while memory isolation stays in it.

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
