#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! `tb-encode` -- the host-verifiable PURE bit-level encoders/validators of Yuva.
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
//! `#![no_std]` + `#![forbid(unsafe_code)]` + ZERO EXTERNAL deps + ZERO asm, so
//! it builds for the HOST triple under plain `cargo` (the repo deliberately
//! keeps `-Zbuild-std` out of the global `.cargo/config.toml`). That is what
//! lets `cargo kani -p tb-encode` model-check the EXACT SAME encoders the
//! kernel runs, with NO model drift and WITHOUT dragging `tb-hal`'s
//! `target_arch` inline asm into CBMC. The ONE allowed workspace-internal
//! dependency is `brand` -- the project-identity crate every name-bearing
//! wire/witness byte (domain separators, wire magics, the disk magic) derives
//! from; it is itself no_std + forbid(unsafe) + zero-dep + consts-only, so it
//! adds nothing to the proof surface.
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
//!  * [`inferwire`] -- the M30 verified INFERENCE-TRANSPORT wire codec: the
//!    typed, fixed-header, LENGTH-PREFIXED, injective [`inferwire::InferFrame`]
//!    (house magic `0x5958`; magic/ver/kind{ECHO_REQ,ECHO_RESP,ERR}/reserved-
//!    zero flags/req_id correlation u64/challenge[16]/nonce[16]/peer_id/tag[16]/
//!    payload_len u32 prefix/payload cap 1024) the kernel exchanges with a HOST
//!    peer over the modern virtio-console channel; `inferwire::canon`/`decode`
//!    are TOTAL + fail-closed (bad magic/ver/reserved/kind, oversize length, or
//!    truncation -> None, the opframe_rx discipline), `inferwire::
//!    resp_binds_req` is the correlation iff-theorem, `inferwire::echo_tag` is
//!    the host-keyed echo MAC -- EXACTLY ONE domain-separated [`khash`] call,
//!    `khash(K, "YUVA-M30-ECHO-V1" || peer_id || nonce || challenge ||
//!    body)[..16]`, binding the challenge + host nonce + lane peer_id INSIDE
//!    the MAC (the M28/Terrapin lesson) -- and `inferwire::verify_echo` is the
//!    kernel-scope leg-1 verifier (bind + challenge-echo + body-bitexact + tag
//!    recompute, conjunctive fail-closed). `inferwire::FrameAccum` (the
//!    [`ipc_frame::BoundedRing`] fixed-capacity pattern, length-delimited)
//!    re-frames the byte STREAM lane fail-closed with scan-to-next-magic
//!    resync and a proven never-overflow bound. HONEST (machine-tokened):
//!    `echo=HOST-KEYED-VERIFIED` is KERNEL-SCOPE (khash-correctness of what
//!    arrived against the channel-revealed key -- NEVER loopback exclusion,
//!    which lives in the run-script cross-process guard); the host key is
//!    `key=HOST-CUSTODIED-PER-RUN` (custody, not confidentiality -- K is
//!    cleartext on the channel via the `INFER_KEY_REVEAL_LEN` trailer);
//!    `backend=ECHO-ONLY` (transport only, no inference semantics until M31);
//!    `sec=ASSUMED-FROM-LITERATURE` is inherited from [`khash`] -- NO symbolic
//!    collision/preimage/PRF harness exists, deliberately.
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
//!  * [`khash`] -- the M29 verified KEYED-HASH primitive leaf: BLAKE2s-256
//!    (RFC 7693) in its NATIVE KEYED MODE (`khash::khash(key32, msg) -> tag32`,
//!    key zero-padded into data block 0 per §2.5/§2.10) plus the unkeyed form
//!    (`khash::uhash` -- the #74 `prov_hash` successor body and the #75
//!    Merkle-node hash), a one-shot API over a single contiguous slice
//!    (deliberately NOT init/update/final). Pure wrapping 32-bit ARX, zero
//!    deps, no float; .rodata = the 32-byte IV + 160-byte sigma schedule.
//!    `khash::kat_ok` recomputes the OFFICIAL vectors (RFC 7693 Appendix B +
//!    the BLAKE2 reference KAT) through the real compression -- the boot
//!    self-test earns `kat=RFC7693-PASS` from it, fail-closed. HONEST
//!    (machine-tokened): implementation totality/determinism/KAT-correctness/
//!    tamper-sensitivity are PROVEN (Kani, concrete inputs -- the #49
//!    discipline); collision/preimage/PRF/forgery resistance of the primitive
//!    is ASSUMED-FROM-LITERATURE (Luykx-Mennink-Neves FSE 2016 keyed-mode
//!    PRF proof; attack record ~7/10 rounds, pseudo settings only); NO
//!    symbolic security harness exists, deliberately. `sidechannel=NOT-CLAIMED`
//!    (constant-time-SHAPED only); RFC 7693 is informational, not a NIST
//!    standard (`prim=BLAKE2S-256` names the trade).
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
//!    bytes), the 256-bit digest (`prov::prov_hash` -- BLAKE2s-256 unkeyed via
//!    the verified M29 [`khash`] leaf since M29 stage C; the retired FNV-era
//!    structural digest's "NOT cryptographic" concession closed -- primitive
//!    security `sec=ASSUMED-FROM-LITERATURE`), the running per-agent fold step
//!    (`prov::chain_mix` -- `head' = mix(head, entry_id)`, tamper-sensitive in
//!    every input byte) and the inclusion verifier (`prov::verify_inclusion` --
//!    accept IFF `recompute(leaf, siblings) == head`) behind a per-agent append-
//!    only hash-chain ledger over the M13 substrate. `tb-hal` CALLS these next to
//!    the write/forget/skill-admit mutation sites; the boot self-test proves any
//!    single-byte tamper of a committed entry invalidates the head AND its
//!    inclusion proof. Cryptographic (khash/BLAKE2s) tamper-evidence since
//!    M29-C, assumption-conditional (`sec=ASSUMED-FROM-LITERATURE`) -- a SIGNED
//!    root (authenticity) remains the tracked successor.
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
//!    replay-determinism + tamper-evidence (cryptographic since M29-C,
//!    `sec=ASSUMED-FROM-LITERATURE`) -- NOT policy validity
//!    (deterministic logging -> degenerate propensity; validity is M24's burden).
//!  * [`exittel`] -- the M26 verified EL2 EXIT-TELEMETRY codec: turns the already-
//!    Kani-proven [`el2_trap::classify_exit`] guest-exit demux into a BOUNDED, no-float,
//!    injective telemetry record. `exittel::bucket_index` is an integer log2 cost-proxy
//!    bucket (`leading_zeros`-based, the OTel exponential-histogram idea without the
//!    float), `exittel::ExitHistogram` is a direct-mapped SATURATING per-class counter
//!    (exact counts over the small closed `ExitClass` set, no sketch collisions), the
//!    fixed-width injective `exittel::canon`/`decode` encode an `ExitTelemetryRecord`
//!    {kind, exit_class, bucket, vmid, count, logical_time}, and the per-instance
//!    `tel_head` fold REUSES the M22 [`prov`] leaf verbatim (`exittel::tel_append` /
//!    `tel_chain_mix` / `tel_verify_inclusion` / `tel_head_witness` -- NO new fold
//!    math). PRODUCER-ONLY: the telemetry is recorded + folded, NOT fed to any policy
//!    whose decisions change the future exit distribution (the confounding loop the M24
//!    adversary named is structurally avoided); the marker emits
//!    `signal=OBSERVATIONAL-NONCAUSAL` so it cannot claim a causal state-signal. Claims
//!    injective bounded encoding + replay-determinism + tamper-evidence (the M23 claim
//!    set; cryptographic since M29-C, `sec=ASSUMED-FROM-LITERATURE`); the `tel_head` is
//!    SEPARATE from the M23 `xp_head` (zero regression).
//!  * [`opframe`] -- the M25 verified OPERATOR-TRANSCRIPT codec: the typed, fixed-
//!    header, LENGTH-PREFIXED, injective [`opframe::OpFrame`] encoder (`opframe::canon`
//!    / `opframe::decode` / `opframe::canon_len` -- magic/ver/kind/sev/partition +
//!    strictly-monotone `seq` + `t_logical` + `prev_head` + a `payload_len` u32 prefix
//!    so distinct frames -> distinct bytes; TOTAL + fail-closed on a too-small buffer,
//!    a bad magic/version/reserved-bit, an out-of-band OTel severity, OR the held-out
//!    partition) the OS emits over serial to SURFACE what it recorded (M23) + decided
//!    (M24) to a human exogenous oracle (the COMMUNICATION pillar). The running per-
//!    instance `op_head` fold REUSES the M22 [`prov`] leaf verbatim (`opframe::
//!    op_append` / `op_chain_mix` / `op_verify_inclusion` / `op_head_witness` -- NO new
//!    fold math); `opframe::fold_frame` is the per-frame fold step (fail-closed: a
//!    rejected/held-out frame never advances the head). `opframe::seq_index_exact`
//!    is the strict-monotone reader check (catches reorder/gap/dup/middle-truncation),
//!    `opframe::intro_binds` proves the genesis INTRO binds the transcript to the LIVE
//!    M22 head (the "which instance am I" attestation -- RATS RFC 9334), and
//!    `opframe::gate_commits_final_seq` is the closing-frame TAIL-truncation guard
//!    (Ma-Tsudik FssAgg). THE LEAKAGE GUARD: `opframe::canon` fail-closes on
//!    [`opframe::partition::SAFETY_HELD_OUT`] so the transcript can NEVER surface a
//!    sealed-partition record (the Seldonian no-snoop invariant -- Thomas Science
//!    2019 + Dwork reusable holdout -- encoded in the encoder). `tb-hal` CALLS these
//!    to emit + self-verify a transcript at boot; the simulated operator-verifier
//!    recomputes the head, asserts seq-monotone + intro-binding + a single-byte tamper
//!    is caught. Claims ONLY tamper-EVIDENCE (cryptographic-hash since M29-C but
//!    KEYLESS) + truncation/reorder/replay
//!    detection (keyed=0, NO forgery-resistance) + instance binding -- NOT crypto
//!    authenticity, NOT that a human replied (oracle=HUMAN-DEFERRED-M26).
//!  * [`opframe_rx`] -- the M28 verified OPERATOR-INBOUND command codec, the RX dual of
//!    [`opframe`]: the typed, fixed-header, LENGTH-PREFIXED, injective
//!    [`opframe_rx::CmdFrame`] (magic, ver, kind(CHALLENGE_REQ/ACTIVATE_CMD/NOP),
//!    reserved, nonce_echo, op_head_bind, seq, cred_a_id, cred_b_id, a payload_len u32
//!    prefix, a trailing keyed MAC) encoder (`opframe_rx::canon` writes the MAC'd bytes
//!    -- everything EXCEPT the trailing mac; `opframe_rx::decode` recovers the frame and
//!    splits canon|mac; both TOTAL and fail-closed on a bad magic/ver/reserved/unknown-
//!    kind or truncation) by which a SIMULATED enrolled verifier answers the OS's
//!    freshness CHALLENGE and submits a DUAL-AUTHORIZED `ACTIVATE_CMD` bound to the LIVE
//!    M22 head -- the exogenous-oracle CLOSURE of the M23->M27 learning loop.
//!    `opframe_rx::key_evolve` is the forward key evolution (M29: the domain-
//!    separated keyed-PRF call `khash(key, "YUVA-KEY-EVOLVE-V1")` -- the
//!    Bellare-Yee reduction shape, conditional on the tokened PRF assumption +
//!    the seam-TESTED old-key erasure), `opframe_rx::compute_mac` is the KEYED
//!    MAC (M29: the DERIVE-THEN-MAC `khash(khash(key_a, "YUVA-OPCMD-KDF-V1" ||
//!    key_b), canon)[..MAC_LEN]` over the verified [`khash`] BLAKE2s-256 leaf --
//!    the M28 nested-FNV envelope RETIRED; NO new hash math), and
//!    `opframe_rx::decode_and_verify` returns `Accept` IFF the frame decodes, is an
//!    ACTIVATE_CMD, echoes the expected nonce (FRESHNESS), binds the live head (the
//!    Terrapin HEAD-BINDING), carries two DISTINCT credentials (DUAL-CUSTODY two-person
//!    rule), AND the recomputed keyed MAC matches; else the precise reject
//!    (`RejectStale`/`RejectWrongHead`/`RejectSingleCred`/`RejectBadMac`/`NotActivate`/
//!    `Malformed`). `tb-hal` CALLS these to play a SIMULATED enrolled verifier at boot;
//!    the self-test ACCEPTS the valid command and REJECTS stale-nonce/wrong-head/single-
//!    cred/flipped-MAC. The MAC tier is `mac=KEYED-CRYPTO` (M29 -- assumption-
//!    conditional: the implementation is VERIFIED while the primitive's collision/
//!    preimage/PRF/forgery resistance is `sec=ASSUMED-FROM-LITERATURE`, never proven;
//!    the retired M28 `KEYED-NONCRYPTO` tier is guard-REJECTED); the CI
//!    verifier is a compiled-in test key (`oracle=SIMULATED-ENROLLED-KEY`), NOT a human;
//!    and an accepted command is NECESSARY-NOT-SUFFICIENT -- it does NOT flip `KAN_ACTIVE`
//!    (`kan_active=0`; M24's statistical bar still gates).
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
//!  * [`tpsched`] -- the M27 verified TWO-VMID TIME-PARTITION SCHEDULER math: the
//!    decidable timing geometry of a fixed two-slot major frame -- `tpsched::next_slot`
//!    (round-robin successor, total, neither slot a fixed point -> no VMID starves),
//!    `tpsched::slot_deadline_delta` (the `CNTHP_TVAL_EL2` countdown, clamped up to
//!    `MIN_SLOT_TICKS`), `tpsched::frame_total` (the conserved saturating major-frame
//!    length) -- plus the fixed-width injective `tpsched::canon`/`decode` of a
//!    `SchedDecision` {frame_seq, slot, vmid_from, vmid_to, t_logical} folded into a
//!    `sched_head` via the M22 [`prov`] fold reused verbatim (the sovereignty -> learning
//!    record). The silicon (arm the timer, switch `VTTBR_EL2`/VMID on the PPI) stays in
//!    `tb-hal`. OBSERVATIONAL not learned (fixed round-robin); NOT real-time / NOT
//!    schedulability-proven (`realtime=NOT-CLAIMED`).
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

pub mod abi;
pub mod attest;
pub mod bakeoff;
pub mod blkfmt;
pub mod conductor;
pub mod corpus;
pub mod el2_trap;
pub mod exittel;
pub mod exp;
pub mod explore;
pub mod guestlog;
pub mod inferwire;
pub mod ipc_frame;
pub mod kancell;
pub mod khash;
pub mod lmsig;
pub mod memscore;
pub mod opframe;
pub mod opframe_rx;
pub mod paging;
pub mod prov;
pub mod provhead;
pub mod recall;
pub mod route;
pub mod sha256;
pub mod smmuv3;
pub mod stage2;
pub mod tpsched;
pub mod vmx;

// The Kani proof harnesses. Gated on `cfg(kani)` (set ONLY under `cargo kani`)
// so a normal `cargo build` / `cargo kbuild` never compiles them; they run only
// in the CI Kani lane (`scripts/verify-encode.sh`).
#[cfg(kani)]
mod proofs;
