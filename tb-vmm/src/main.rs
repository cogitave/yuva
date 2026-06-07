//! tb-vmm — TABOS sovereign userspace VMM (the **L1** sovereignty rung).
//!
//! tb-vmm boots the unmodified TABOS kernel ELF through TABOS's OWN boot
//! contract (`tb-boot v0`), entering the guest **directly in 64-bit long mode**
//! over `/dev/kvm` — deleting the PVH ELF note + the A0 32->64 trampoline from
//! the boot path (docs/SOVEREIGNTY-ROADMAP.md §7). It is a `std`, Linux-hosted
//! binary in its own audited-`unsafe` domain, **outside** the framekernel
//! `#![forbid(unsafe_code)]` boundary.
//!
//! Architecture (one module per concern, arch behind a seam):
//! * [`cli`]     — argument parsing + the [`cli::Config`].
//! * [`error`]   — the single [`error::VmmError`] type (no `unwrap` on the boot path).
//! * [`memory`]  — guest RAM (`GuestMemoryMmap`) + `KVM_SET_USER_MEMORY_REGION`.
//! * [`loader`]  — ELF64 `PT_LOAD` loader + TABOS-note 64-bit entry discovery.
//! * [`device`]  — a PIO/MMIO [`device::Bus`] registry (extensible to virtio).
//! * [`serial`]  — a minimal 16550A UART carrying guest output to stdout.
//! * [`vmm`]     — the VM lifecycle + the `KVM_RUN` exit loop.
//! * [`arch`]    — the arch seam; `arch::x86_64::boot` holds the verified
//!                 Firecracker long-mode `KVM_SET_SREGS`/`KVM_SET_REGS` setup.

mod arch;
mod cli;
mod device;
mod error;
mod loader;
mod memory;
mod serial;
mod vmm;

use std::process::ExitCode;

use crate::cli::{Cli, CliAction, Config};
use crate::error::VmmError;
use crate::vmm::{StopReason, Vmm};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    let action = match Cli::parse(args.iter().map(String::as_str)) {
        Ok(action) => action,
        Err(e) => {
            eprintln!("tb-vmm: {e}");
            eprintln!();
            eprint!("{}", cli::USAGE);
            return ExitCode::from(2);
        }
    };

    let config = match action {
        CliAction::Help => {
            print!("{}", cli::USAGE);
            return ExitCode::SUCCESS;
        }
        CliAction::Run(config) => config,
    };

    match run(config) {
        Ok(stop) => {
            // A clean guest stop (HLT / shutdown) is success — the milestone
            // markers were already streamed to stdout by the serial device.
            let _ = stop;
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("tb-vmm: error: {e}");
            ExitCode::from(1)
        }
    }
}

/// Build and run the VM, returning the reason it stopped.
fn run(config: Config) -> Result<StopReason, VmmError> {
    let print_exit = config.print_exit;
    let mut vmm = Vmm::new(config)?;
    let stop = vmm.run()?;
    if print_exit {
        eprintln!("tb-vmm: guest stopped cleanly: {stop:?}");
    }
    Ok(stop)
}
