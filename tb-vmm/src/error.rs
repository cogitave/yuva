//! The single error type for tb-vmm.
//!
//! Maturity requirement: there is **no `unwrap` on the boot path**. Every
//! fallible step returns [`VmmError`], which carries enough context to diagnose
//! a boot failure (and, for guest faults, the KVM exit reason).

use std::fmt;
use std::path::PathBuf;

use crate::device::BusError;
use crate::loader::LoaderError;

/// All the ways a tb-vmm run can fail.
#[derive(Debug)]
pub enum VmmError {
    /// `/dev/kvm` could not be opened (absent, or no read+write permission).
    KvmInit(kvm_ioctls::Error),
    /// A KVM ioctl failed.
    Kvm(kvm_ioctls::Error),
    /// `KVM_API_VERSION` mismatch (KVM is unusably old/new).
    ApiVersion(i32),
    /// Allocating guest RAM (the anonymous mmap) failed.
    GuestMemoryCreate(String),
    /// A read/write against guest RAM failed (out of range, etc.).
    MemoryAccess(vm_memory::GuestMemoryError),
    /// The kernel image file could not be read.
    KernelRead(PathBuf, std::io::Error),
    /// The kernel ELF could not be parsed/loaded.
    Loader(LoaderError),
    /// Registering a device on a bus failed (address overlap).
    Bus(BusError),
    /// A configuration value is invalid (e.g. cmdline too long for the boot window).
    Config(String),
    /// A feature is not implemented on the current host architecture. Only
    /// constructed on non-x86_64 hosts (see `arch::setup`), so it is dead code
    /// on the x86_64 build — hence the targeted allow.
    #[cfg_attr(target_arch = "x86_64", allow(dead_code))]
    Unsupported(&'static str),
    /// The wall-clock run guard fired before the guest halted.
    Timeout {
        /// The configured guard, in seconds.
        secs: u64,
    },
    /// The VM-exit budget was exhausted (guard against a hung guest).
    ExitBudget(u64),
    /// `KVM_EXIT_FAIL_ENTRY`: the vCPU could not enter the guest.
    GuestFault {
        /// Hardware entry-failure reason word.
        reason: u64,
        /// The vCPU index reported by KVM.
        cpu: u32,
    },
    /// `KVM_EXIT_INTERNAL_ERROR`: KVM hit an internal/emulation error.
    InternalError,
    /// `KVM_EXIT_SHUTDOWN`: the guest triple-faulted or reset. For a TABOS boot
    /// this means the kernel crashed before halting — a failure, not a clean stop.
    GuestShutdown,
    /// `KVM_EXIT_SYSTEM_EVENT`: an unexpected ACPI/PSCI system event. The TABOS
    /// kernel stops via `HLT`, so any system event here is treated as a failure.
    /// Carries the KVM system-event type.
    SystemEvent(u32),
}

impl fmt::Display for VmmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VmmError::KvmInit(e) => write!(
                f,
                "could not initialise KVM (open /dev/kvm): {e}. Ensure the host exposes \
                 /dev/kvm and the current user can read+write it (e.g. `sudo chmod 666 /dev/kvm`)"
            ),
            VmmError::Kvm(e) => write!(f, "KVM ioctl failed: {e}"),
            VmmError::ApiVersion(v) => {
                write!(f, "unexpected KVM_API_VERSION {v} (tb-vmm requires 12)")
            }
            VmmError::GuestMemoryCreate(e) => write!(f, "failed to allocate guest RAM: {e}"),
            VmmError::MemoryAccess(e) => write!(f, "guest memory access failed: {e}"),
            VmmError::KernelRead(path, e) => {
                write!(f, "could not read kernel image `{}`: {e}", path.display())
            }
            VmmError::Loader(e) => write!(f, "kernel ELF load failed: {e}"),
            VmmError::Bus(e) => write!(f, "device bus error: {e}"),
            VmmError::Config(msg) => write!(f, "invalid configuration: {msg}"),
            VmmError::Unsupported(msg) => write!(f, "unsupported: {msg}"),
            VmmError::Timeout { secs } => {
                write!(f, "guest did not halt within the {secs}s run guard")
            }
            VmmError::ExitBudget(n) => {
                write!(f, "VM-exit budget of {n} exhausted (guest appears hung)")
            }
            VmmError::GuestFault { reason, cpu } => write!(
                f,
                "KVM_EXIT_FAIL_ENTRY on vCPU {cpu}: hardware_entry_failure_reason={reason:#x}"
            ),
            VmmError::InternalError => write!(f, "KVM_EXIT_INTERNAL_ERROR"),
            VmmError::GuestShutdown => write!(
                f,
                "KVM_EXIT_SHUTDOWN: guest triple-faulted or reset before halting \
                 (the kernel crashed during boot)"
            ),
            VmmError::SystemEvent(ev) => write!(
                f,
                "KVM_EXIT_SYSTEM_EVENT type={ev}: unexpected system event \
                 (a TABOS kernel is expected to stop via HLT)"
            ),
        }
    }
}

impl std::error::Error for VmmError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VmmError::KvmInit(e) | VmmError::Kvm(e) => Some(e),
            VmmError::MemoryAccess(e) => Some(e),
            VmmError::KernelRead(_, e) => Some(e),
            VmmError::Loader(e) => Some(e),
            VmmError::Bus(e) => Some(e),
            _ => None,
        }
    }
}

impl From<kvm_ioctls::Error> for VmmError {
    fn from(e: kvm_ioctls::Error) -> Self {
        VmmError::Kvm(e)
    }
}

impl From<vm_memory::GuestMemoryError> for VmmError {
    fn from(e: vm_memory::GuestMemoryError) -> Self {
        VmmError::MemoryAccess(e)
    }
}

impl From<LoaderError> for VmmError {
    fn from(e: LoaderError) -> Self {
        VmmError::Loader(e)
    }
}

impl From<BusError> for VmmError {
    fn from(e: BusError) -> Self {
        VmmError::Bus(e)
    }
}
