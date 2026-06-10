#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! `tb-encode` -- the host-verifiable PURE bit-level encoders/validators of TABOS.
//!
//! This crate is the SINGLE SOURCE OF TRUTH for the *value computation* that
//! sits one millimetre in front of the kernel's silicon-`unsafe`: the bit
//! algebra that decides WHAT a VMX control word, an EPT/page-table entry, a TSS
//! descriptor base, or an IPC wire frame should be. The actual `unsafe`
//! `vmwrite`/`write_volatile`/asm that COMMITS that value to hardware stays in
//! [`tb-hal`](../tb_hal/index.html); `tb-hal` calls the functions here and keeps
//! the store next to the just-computed value, so the silicon side is
//! byte-identical to before this crate existed -- only now the value is computed
//! by provably-safe code.
//!
//! ## Why a separate crate (mirrors `tb-boot` / `tb-caps-core`)
//!
//! `#![no_std]` + `#![forbid(unsafe_code)]` + ZERO deps + ZERO asm, so it builds
//! for the HOST triple under plain `cargo` (the repo deliberately keeps
//! `-Zbuild-std` out of the global `.cargo/config.toml`). That is what lets
//! `cargo kani -p tb-encode` model-check the EXACT SAME encoders the kernel
//! runs, with NO model drift and WITHOUT dragging `tb-hal`'s `target_arch`
//! inline asm into CBMC.
//!
//! ## Modules
//!
//!  * [`vmx`] -- the control-MSR ADJUST gate (the #1 cause of silent VM-entry
//!    failure), the CR0/CR4 fixed-bit clamp, and the TSS-descriptor base decode.
//!  * [`paging`] -- the shared radix-512 page-table entry algebra
//!    (`make_entry`/`entry_addr`/`level_index`/`entry_is_valid` + the level
//!    shifts and the `[47:12]` address mask) plus the EPT and standard-paging
//!    leaf/non-leaf/EPTP entry encoders.
//!  * [`ipc_frame`] -- the mature 16-byte on-wire IPC [`MessageFrame`] codec
//!    (`encode`/`decode`, fail-closed on malformed input) and a fixed-capacity
//!    [`ipc_frame::BoundedRing`] with FIFO + capacity invariants.
//!  * [`route`] -- the M16 `model:`-scheme routing helpers lifted out of
//!    `tb-hal::infer`: the panic-free `model:<provider>/<path>` grammar parser
//!    (`route::parse_scheme`) and the longest-prefix-match routing decision
//!    (`route::longest_prefix_index`) over the in-kernel route-key literals.
//!  * [`memscore`] -- the M13 memory-recall RANKING MATH lifted out of
//!    `tb-hal::mem`: the pure fixed-point `log2`/`ln`, the ACT-R Base-Level
//!    Activation `bla_raw` that drives recall + the M17 FORGET sweep, the
//!    `minmax` score normalizer, and the M18 frozen-evaluator `skill_transform`
//!    -- panic/overflow-freedom + bounds proven over UNTRUSTED memory metadata.
//!  * [`kancell`] -- the M21 forget/demote POLICY-CELL math lifted out of
//!    `tb-hal::mem`: a verified fixed-point ADDITIVE-policy leaf (a piecewise-
//!    LINEAR integer GAM, NOT a neural net -- the knots are frozen offline and
//!    shipped as a `const` i16 Q4.11 table) that ranks ONLY inside the M17
//!    heuristic safety envelope. `kan_spline_eval` interpolates one univariate
//!    spline on a uniform power-of-2 grid (segment index by `>>`, no divide),
//!    `kan_score` sums `KAN_FEATURES` splines + bias + flag terms in a SATURATING
//!    `i64` and final-clamps into the M17 `DEMOTE_BAND` (the tautological output
//!    bound), and `kan_table_is_monotone` / `kan_table_overflow_safe` are the
//!    solver-free MonoKAN + headroom validators the fail-closed loader re-checks
//!    in-kernel at load -- totality / overflow-freedom / structural monotonicity /
//!    determinism / envelope-no-widening proven over the INTEGER artifact. SHIPS
//!    DORMANT (the heuristic floor decides until an offline trace bake-off gate).
//!  * [`stage2`] -- the L2.1 aarch64 second-stage (stage-2) descriptor + control
//!    algebra: the `s2_leaf_2mib`/`s2_leaf_4k`/`s2_table` VMSAv8-64 stage-2 entry
//!    encoders (S2AP=RW, MemAttr Normal-WB, mandatory AF, block/page/table low
//!    bits, address via the shared `make_entry`) plus the `vtcr`/`vttbr` packers
//!    -- the ARM analog of the EPT encoders, proven well-formed.
//!  * [`smmuv3`] -- the aL2.6 Arm SMMUv3 (IHI 0070) IOMMU algebra: the
//!    stage-2-only Stream Table Entry packer (`ste_s2` + the `ste_*` accessors,
//!    `Config==0b110`), the `ste_vtcr_from_vtcr_el2` LEMMA projecting the CPU's
//!    `VTCR_EL2` into the STE `VTCR` slot (the "SMMU stage-2 IS the CPU stage-2"
//!    bit-identity), the `cmd_cfgi_ste`/`cmd_tlbi_s12_vmall`/`cmd_sync`
//!    command-queue encoders, and the `strtab_base`/`strtab_base_cfg`/
//!    `cmdq_base`/`eventq_base` register packers -- reusing `stage2::vtcr`,
//!    proven bit-faithful (the IOMMU twin of the stage-2 geometry).
//!  * [`blkfmt`] -- the M20 durable-persistence codecs: the virtio-blk request
//!    header (`{le32 type, le32 reserved, le64 sector}`; IN=0/OUT=1/FLUSH=4) +
//!    closed status decode, the 512-byte log-structured superblock
//!    (magic/version/gen/per-Region watermarks + FNV-1a-64 checksum, total fail-
//!    closed decode), the 24-byte record frame (region/len/seq + FNV-1a-32
//!    payload CRC, the torn-tail rejector) + the 48-byte LE Episode body, and the
//!    const fixed-partition sector/extent math (`region_extent`/`record_sector`,
//!    no-overflow/in-extent) -- the PURE bytes the `VirtioBlkStore` two-phase
//!    commit reads/writes, byte-identical to a Kani-proven model.
//!  * [`prov`] -- the M22 memory-PROVENANCE LEDGER math: the canonical, injective,
//!    LENGTH-PREFIXED [`prov::ProvEntry`] encoder (`prov::canon` -- fixed field
//!    order + an explicit parent-count prefix so distinct entries -> distinct
//!    bytes), the 256-bit STRUCTURAL digest (`prov::prov_hash` -- four domain-
//!    separated, already-Kani-proven `blkfmt::fnv1a64` lanes + a length domain-
//!    separator, NOT cryptographic), the running per-agent fold step
//!    (`prov::chain_mix` -- `head' = mix(head, entry_id)`, tamper-sensitive in
//!    every input byte) and the inclusion verifier (`prov::verify_inclusion` --
//!    accept IFF `recompute(leaf, siblings) == head`) behind a per-agent append-
//!    only hash-chain ledger over the M13 substrate. `tb-hal` CALLS these next to
//!    the write/forget/skill-admit mutation sites; the boot self-test proves any
//!    single-byte tamper of a committed entry invalidates the head AND its
//!    inclusion proof. Structural tamper-evidence only -- a crypto hash + signed
//!    root is a tracked successor.
//!  * [`exp`] -- the M23 verified EXPERIENCE CODEC: the fixed-field, FIXED-WIDTH
//!    injective [`exp::ExperienceRecord`] encoder (`exp::canon` / `exp::decode` /
//!    `exp::canon_len` -- every field at a fixed offset, so distinct records ->
//!    distinct bytes, total + fail-closed on a too-small buffer) over the M17
//!    forget/recall decisions: the quantized `feats` (on the EXACT `kancell` grid),
//!    the heuristic envelope verdict + action, the COUNTERFACTUAL `kan_score_shadow`
//!    the DORMANT cell would produce, plus the RESERVED-but-unset
//!    `logging_propensity_q` / `logging_policy_kind` / present-`Unset`
//!    [`exp::OutcomeLabel`] fields (the schema-stability reserve-now refinement so
//!    M24 populating them cannot shift the canonical bytes). `exp::replay_shadow`
//!    re-derives the dormant `kan_score` BIT-IDENTICALLY from a recorded `feats` row
//!    (the headline replay-determinism claim -- achievable because the kancell is
//!    integer / no-float), `exp::ExpRing` is the fixed-capacity drop-oldest in-RAM
//!    replay buffer (no alloc, no panic at capacity), and the per-agent `xp_head`
//!    fold REUSES the M22 [`prov`] leaf verbatim (`exp::xp_append` /
//!    `exp::xp_chain_mix` / `exp::xp_verify_inclusion` / `exp::xp_head_witness` --
//!    NO new fold math). `tb-hal` CALLS these next to the M17 forget/recall sites;
//!    `KAN_ACTIVE` stays `false` (the shadow changes zero demotes). Claims ONLY
//!    replay-determinism + structural tamper-evidence -- NOT policy validity
//!    (deterministic logging -> degenerate propensity; validity is M24's burden).
//!  * [`explore`] -- the M24 SHIELDED EPSILON-GREEDY exploration math: the
//!    closed-form logging PROPENSITY `explore_propensity_q(eps_num, eps_den, m,
//!    is_greedy) -> u16` (Open Bandit Pipeline arXiv:2008.07146) M24 stamps into
//!    the M23-reserved `logging_propensity_q` field. A rational `eps = eps_num/
//!    eps_den` flips the kancell-greedy-vs-heuristic choice ONLY among the
//!    already-cleared candidate set the frozen M17 shield emits (Alshiekh
//!    arXiv:1708.08611), restoring positivity (`pi_b in (0,1)`) so off-policy
//!    evaluation is identifiable over the explored support. SATURATING integer
//!    mul/div only -- TOTAL, in `[1, 1000]` for every cleared action when
//!    `eps_num > 0` and `m >= 1`, with the `m == 1` SINGLETON guard returning
//!    exactly `1000` (a forced action can never be explored -> routed to the
//!    partial-id bound). NO float; the explore choice is logged but, with
//!    `KAN_ACTIVE == false`, NEVER changes the live demote.
//!  * [`bakeoff`] -- the M24 HONEST-GATE estimator math: the deterministic 3-way
//!    right-censored survival `survival_label(decision_tick, now_tick,
//!    first_read_touch_tick, W) -> {Negative, Positive, Censored}` (Liu
//!    arXiv:2007.15859 forward-reuse-distance / Chapelle KDD'14 delayed-feedback
//!    censoring -- exhaustive + mutually-exclusive + monotone-resolution over the
//!    unfiltered-`read()` re-touch path), the Manski + Lipschitz-smoothness
//!    `value_lower_bound` (Khan-Saveski-Ugander arXiv:2305.11812 -- a closed-form
//!    nearest-neighbour smoothness sweep over the quantized kancell grid, no
//!    divide/recursion, SOUND, rounds DOWN), the Maurer-Pontil empirical-Bernstein
//!    `eb_lower_bound(sum, sum_sq, n, range, delta)` integer LOWER confidence bound
//!    (arXiv:0907.3740), and the conjunctive ONE-SHOT `gate_clears` HCPI activation
//!    test (Thomas HCPI ICML'15 / Seldonian Science 2019) -- `V_lower(kancell) -
//!    V_upper(heuristic) >= MARGIN` over a distribution-shifted held-out split, AND
//!    the re-asserted M21 envelope-no-widening proof. On synthetic traces the gate
//!    does NOT clear (`gate-not-met`, the cell stays DORMANT) -- the designed,
//!    correct outcome. Reuses `kancell` (grid + `kan_score` + `DEMOTE_BAND`),
//!    `exp::OutcomeLabel`/`policy_kind`, and `memscore::ln_fixed`; NO float, all
//!    saturating integer, totality/soundness/round-down Kani-proven.
//!  * [`el2_trap`] -- the L2.1 EL2 trap-syndrome decoders: `esr_ec`/`esr_dfsc`/
//!    `esr_is_translation_fault`/`esr_wnr`/`esr_s1ptw` + `hpfar_fault_ipa`/
//!    `far_page_offset`, the pure `ESR_EL2`/`HPFAR_EL2`/`FAR_EL2` bit extraction
//!    the stage-2 demand-fault handler classifies aborts with (total, no panic);
//!    plus the L2.3 TRAP-and-EMULATE ISS decoders -- the SYS64 sysreg ISS
//!    (`sysreg_iss_op0/op1/op2/crn/crm/rt/is_read` + `sysreg_iss_sys_val` /
//!    `SYSREG_ISS_SYS_MASK` / `SYS_CONTEXTIDR_EL1`) and the Data-Abort MMIO ISS
//!    (`dabt_iss_isv/sas/sse/srt/sf/ar` + `dabt_access_size_bytes` /
//!    `dabt_is_emulatable`), the bit extraction the trap-and-emulate handler
//!    decodes the trapped MSR/MRS and the MMIO LDR/STR transfer register with;
//!    plus the aL2.5 GICv2 GICH_LRn list-register encoder (`gich_lr_encode` +
//!    `lr_state`/`lr_virtid`/`lr_is_retired` + `gich_hcr`/`vtr_list_regs` and
//!    the `GICH_LR_STATE_*` / field-shift constants) -- the pure value the EL2
//!    monitor stores into GICH_LR0 to SOFTWARE-INJECT a virtual interrupt
//!    (vINTID/pINTID/state/priority/group/HW/EOI) and the readback decode the
//!    done-side LR-retired completion check reads.
//!
//! ## Verification
//!
//! The Kani harnesses live in `src/proofs.rs`, gated `#[cfg(kani)]` so a normal
//! `cargo build` / `cargo kbuild` never compiles them. They prove the
//! control-MSR adjust legality gate over ALL inputs, encode/decode round-trip
//! identity, total/fail-closed decoding, and the page-table/EPT entry bit
//! invariants. See `scripts/verify-encode.sh` (DoD marker `V1: kani-encoders OK`).

pub mod bakeoff;
pub mod blkfmt;
pub mod el2_trap;
pub mod exp;
pub mod explore;
pub mod ipc_frame;
pub mod kancell;
pub mod memscore;
pub mod paging;
pub mod prov;
pub mod route;
pub mod smmuv3;
pub mod stage2;
pub mod vmx;

// The Kani proof harnesses. Gated on `cfg(kani)` (set ONLY under `cargo kani`)
// so a normal `cargo build` / `cargo kbuild` never compiles them; they run only
// in the CI Kani lane (`scripts/verify-encode.sh`).
#[cfg(kani)]
mod proofs;
