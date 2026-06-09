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
//!  * [`stage2`] -- the L2.1 aarch64 second-stage (stage-2) descriptor + control
//!    algebra: the `s2_leaf_2mib`/`s2_leaf_4k`/`s2_table` VMSAv8-64 stage-2 entry
//!    encoders (S2AP=RW, MemAttr Normal-WB, mandatory AF, block/page/table low
//!    bits, address via the shared `make_entry`) plus the `vtcr`/`vttbr` packers
//!    -- the ARM analog of the EPT encoders, proven well-formed.
//!  * [`el2_trap`] -- the L2.1 EL2 trap-syndrome decoders: `esr_ec`/`esr_dfsc`/
//!    `esr_is_translation_fault`/`esr_wnr`/`esr_s1ptw` + `hpfar_fault_ipa`/
//!    `far_page_offset`, the pure `ESR_EL2`/`HPFAR_EL2`/`FAR_EL2` bit extraction
//!    the stage-2 demand-fault handler classifies aborts with (total, no panic);
//!    plus the L2.3 TRAP-and-EMULATE ISS decoders -- the SYS64 sysreg ISS
//!    (`sysreg_iss_op0/op1/op2/crn/crm/rt/is_read` + `sysreg_iss_sys_val` /
//!    `SYSREG_ISS_SYS_MASK` / `SYS_CONTEXTIDR_EL1`) and the Data-Abort MMIO ISS
//!    (`dabt_iss_isv/sas/sse/srt/sf/ar` + `dabt_access_size_bytes` /
//!    `dabt_is_emulatable`), the bit extraction the trap-and-emulate handler
//!    decodes the trapped MSR/MRS and the MMIO LDR/STR transfer register with.
//!
//! ## Verification
//!
//! The Kani harnesses live in `src/proofs.rs`, gated `#[cfg(kani)]` so a normal
//! `cargo build` / `cargo kbuild` never compiles them. They prove the
//! control-MSR adjust legality gate over ALL inputs, encode/decode round-trip
//! identity, total/fail-closed decoding, and the page-table/EPT entry bit
//! invariants. See `scripts/verify-encode.sh` (DoD marker `V1: kani-encoders OK`).

pub mod el2_trap;
pub mod ipc_frame;
pub mod memscore;
pub mod paging;
pub mod route;
pub mod stage2;
pub mod vmx;

// The Kani proof harnesses. Gated on `cfg(kani)` (set ONLY under `cargo kani`)
// so a normal `cargo build` / `cargo kbuild` never compiles them; they run only
// in the CI Kani lane (`scripts/verify-encode.sh`).
#[cfg(kani)]
mod proofs;
