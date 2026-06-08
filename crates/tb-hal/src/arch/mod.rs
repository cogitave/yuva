//! Architecture dispatch for `tb-hal`.
//!
//! `lib.rs` calls the arch primitives through this module; they are re-exported
//! here from whichever per-arch submodule matches the build target. The
//! submodules (`arch/x86_64/{mod,boot,serial,gdt,idt,trap,sched}.rs`,
//! `arch/aarch64/{mod,boot,serial,trap,vectors,sched}.rs`) contain ALL of the
//! crate's `unsafe` + assembly and are emitted separately; THIS file only wires
//! them up.
//!
//! INTERNAL CONTRACT each `arch/<arch>/mod.rs` must satisfy (see BUILD.md):
//!   * `pub fn serial_init();`
//!   * `pub fn serial_write_byte(b: u8);`
//!   * `pub fn halt() -> !;`
//!   * `pub fn install_traps();`   (M1 — load GDT/TSS/IDT or set VBAR_EL1)
//!   * `pub fn breakpoint();`      (M1 — int3 / brk #0)
//!   * `pub fn task_stack_init(stack: &mut [usize], entry: fn()) -> usize;`
//!     (M2 — fabricate the INITIAL context frame at the 16-aligned-down top of
//!      `stack` so the first switch into the task "returns" into `entry`,
//!      returning the initial saved SP. x86_64: `[entry]` at a 16-aligned slot
//!      as the return address + 6 zeroed callee-saved slots {rbx, rbp,
//!      r12..r15} below it, so `entry` observes RSP % 16 == 8 — the psABI
//!      §3.2.2 post-`call` state. aarch64: a 96-byte stp/ldp frame holding
//!      {x19..x28, x29(FP), x30(LR)} with x30 = entry and the rest zeroed; SP
//!      stays 16-aligned per AAPCS64 §6.4.5.1.)
//!   * `pub unsafe extern "C" fn ctx_switch(prev_sp_save: *mut usize,
//!      next_sp: usize);`
//!     (M2 — naked cooperative switch: push/stp the CALLEE-SAVED set of the
//!      current task onto its own stack — x86-64 SysV psABI §3.2.1 {rbx, rbp,
//!      r12, r13, r14, r15}; AAPCS64 §6.1.1 {x19..x28, x29, x30} — store the
//!      resulting SP to `*prev_sp_save`, load `next_sp` into SP, pop/ldp the
//!      same set and return into the next task. The resume address travels as
//!      the on-stack return address (x86_64) / in x30+`ret` (aarch64).)
//!   * plus the boot entry (`_start`, via `global_asm!`) and the
//!     XEN_ELFNOTE_PHYS32_ENTRY note (x86_64 only), which the linker keeps.

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use self::x86_64::{
    breakpoint, ctx_switch, halt, heap_window, install_traps, map_heap_frames, mmu_init,
    mmu_selftest, pmm_collect_regions, serial_init, serial_write_byte, task_stack_init, user_demo,
};

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use self::aarch64::{
    breakpoint, ctx_switch, halt, heap_window, install_traps, map_heap_frames, mmu_init,
    mmu_selftest, pmm_collect_regions, serial_init, serial_write_byte, task_stack_init, user_demo,
};

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!(
    "tb-hal supports only x86_64 and aarch64 (the two Firecracker-class arches); \
     build with --target targets/x86_64-tabos-none.json or \
     targets/aarch64-tabos-none.json"
);
