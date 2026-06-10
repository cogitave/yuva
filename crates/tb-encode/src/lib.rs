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

pub mod blkfmt;
pub mod el2_trap;
pub mod ipc_frame;
pub mod kancell;
pub mod memscore;
pub mod paging;
pub mod route;
pub mod smmuv3;
pub mod stage2;
pub mod vmx;

// The Kani proof harnesses. Gated on `cfg(kani)` (set ONLY under `cargo kani`)
// so a normal `cargo build` / `cargo kbuild` never compiles them; they run only
// in the CI Kani lane (`scripts/verify-encode.sh`).
#[cfg(kani)]
mod proofs;
