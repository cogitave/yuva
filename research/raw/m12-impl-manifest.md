# M12 — agent runtime (AgentProcess) — implementation manifest

M12 was implemented via a **write-to-disk implementation agent** (not the structured-output
workflow): the agent-runtime edit-set is too large to emit as a single structured output
(the generate agents blew the 64000-output-token cap, leaving the finalize with nothing to
consume). Recovery: the workflow's 3 intact design results (recon + research) were extracted
to `m12-design.json` and fed to a foreground implementation agent that wrote the code
directly, then built + booted both arches to green. Independently re-verified before commit.

## Key design decisions

- **User-mode involuntary preemption reuses M9 `ctx_switch` UNCHANGED.** A timer IRQ at
  CPL3/EL0 makes the CPU push the interrupt frame onto the agent's own kernel stack
  (x86_64 from `TSS.rsp0`; aarch64 from `SP_EL1`), so the existing `__alltraps` / `__vec_irq`
  → `schedule` → `ctx_switch` path applies verbatim. New `static TASK_KSTACK_TOP[]` in lib.rs
  (next to M10's `TASK_AS[]`); `yield_to` programs `TSS.rsp0` before `ctx_switch` when the
  next task is a user task (no-op on aarch64).
- **First activation** uses a fabricated frame whose `ret` lands in `agent_launch`, which
  `iretq`/`eret`s to ring3/EL0 **preemptible** (x86 RFLAGS IF=1; aarch64 SPSR `0x340`, I clear).
- **AgentProcess** = M10 AddressSpace + M11 HandleTable + M9 Task + AgentManifest. Each agent's
  user code page, user stack, and the M11 cap-syscall page are mapped into its OWN address
  space root via `map_user_in_root` (U/S at every level / AP_EL0).
- **Born with handles, zero setup calls** — `agent_spawn` mints the memory-home / bootstrap /
  budget handles in the agent's table and delivers them in the user-entry register file
  (rdi/rsi on x86; x0/x1 on aarch64).
- **Agent cap syscall** uses a fresh vector (x86 `int 0x82`; aarch64 svc) → runs the pure-safe
  `caps::dispatch` on `CURRENT_TASK`'s table → status back in rax/x0.
- **aarch64 EL0 IRQ**: vector slot `0x480` re-pointed `__vec_other` → `__vec_irq` so a
  preempted EL0 agent is handled; `__vec_el0_sync` now `RESTORE_CONTEXT`+`eret`.
- **Parent-only-VA fault test** reuses M10's armed-fault + guarded-resume against the agent's
  own root (parent VA in a vacant `PML4[5]` / `L1[7]`).

## Files changed (17)
crates/tb-hal/src/lib.rs; crates/tb-hal/src/arch/mod.rs;
crates/tb-hal/src/arch/x86_64/{mmu,sched,user,mod}.rs;
crates/tb-hal/src/arch/aarch64/{mmu,sched,user,vectors,mod}.rs;
kernel/src/main.rs; scripts/{run-x86_64,run-aarch64,run-vmm-x86_64,bench-boot}.sh;
docs/ROADMAP-V2.md.

## Verification (both arches, independently re-run)
0-warning `cargo kbuild` on x86_64-tabos-none + aarch64-tabos-none; QEMU boot M0→M12:
```
agent: both agents born with memory-home + bootstrap (zero setup)
agent: permitted syscall Ok + non-manifest syscall Denied (both agents)
agent: involuntary user-mode switches=0x000000000000003c
agent: child fault on a parent-only VA, recovered in the hook
M12: agent OK
```
M2..M11 markers all still print (no regression). tb-vmm/KVM path deferred to CI (no local
/dev/kvm access). Marker: "M12: agent OK".
