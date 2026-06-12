//! Command-line parsing for tb-vmm.
//!
//! Hand-rolled (std `env::args`, no `clap`) to keep the dependency surface
//! minimal and the parsing fully unit-testable as pure logic.

use std::fmt;
use std::path::PathBuf;

/// Usage / help text. Printed for `--help` and on any parse error.
pub const USAGE: &str = "\
tb-vmm — Yuva sovereign userspace VMM (L1)\n\
\n\
USAGE:\n\
    tb-vmm [OPTIONS]\n\
\n\
OPTIONS:\n\
    --kernel <PATH>         Path to the Yuva kernel ELF to boot.\n\
                            [default: target/x86_64-yuva-none/debug/yuva-kernel]\n\
    --mem-mb <N>            Guest RAM in MiB. [default: 256]\n\
    --cmdline <STRING>      Kernel command line passed via tb-boot. [default: \"\"]\n\
    --timeout-secs <N>      Wall-clock guard; the run aborts if the guest does\n\
                            not halt within this many seconds. [default: 30]\n\
    --print-exit            Print the VM-exit reason + vCPU state to stderr.\n\
    --report-spawn          Time the spawn path: print a machine-parseable\n\
                            `spawn-ready-ns=<n> phase-kvm-ns=.. ...` line when\n\
                            the guest writes the boot-ready PIO port (0x510),\n\
                            then keep running until the timeout guard.\n\
    --xport-out <PATH>      M30: write the host-peer witness lines\n\
                            (`xport-harness: peer=TB-VMM-HOST ..`) to PATH\n\
                            instead of stderr — the run script's SEPARATE\n\
                            leg-2 capture stream (guest serial rides stdout;\n\
                            the guest can never write this file).\n\
    --xport-key-out <PATH>  M30: write the per-run host-custodied echo key K\n\
                            as lowercase hex to PATH (the run script's §5.7\n\
                            key-leak negative input — never a witness).\n\
    -h, --help              Print this help.\n";

/// The default kernel image path (the debug build of the custom target).
pub const DEFAULT_KERNEL: &str = "target/x86_64-yuva-none/debug/yuva-kernel";
/// Default guest RAM, in MiB.
pub const DEFAULT_MEM_MB: u64 = 256;
/// Default wall-clock run guard, in seconds.
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;
/// Smallest guest RAM we accept (the kernel image loads at 1 MiB and the boot
/// page tables sit in low memory; 8 MiB is a comfortable floor).
pub const MIN_MEM_MB: u64 = 8;

/// Fully-resolved, validated run configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Path to the kernel ELF to boot.
    pub kernel_path: PathBuf,
    /// Guest RAM size in bytes.
    pub mem_bytes: u64,
    /// Kernel command line (carried to the guest via tb-boot).
    pub cmdline: String,
    /// Wall-clock run guard in seconds.
    pub timeout_secs: u64,
    /// Whether to print exit diagnostics to stderr.
    pub print_exit: bool,
    /// Whether to time the spawn path and print the machine-parseable
    /// `spawn-ready-ns=..` breakdown when the guest writes the boot-ready port.
    pub report_spawn: bool,
    /// M30: where the in-process host peer writes its `xport-harness:` witness
    /// lines (the run script's separate leg-2 capture stream). `None` = stderr.
    pub xport_out: Option<PathBuf>,
    /// M30: where the per-run host-custodied echo key K is written as hex (the
    /// run script's key-leak-negative input). `None` = nowhere (never printed).
    pub xport_key_out: Option<PathBuf>,
}

/// The outcome of parsing argv.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CliAction {
    /// `--help`/`-h`: print usage and exit 0.
    Help,
    /// Run with the resolved configuration.
    Run(Config),
}

/// A CLI parse error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CliError {
    /// An option that requires a value was given without one.
    MissingValue(&'static str),
    /// A numeric option could not be parsed.
    BadNumber { flag: &'static str, value: String },
    /// `--mem-mb` below [`MIN_MEM_MB`].
    MemTooSmall(u64),
    /// An unrecognised argument.
    Unknown(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::MissingValue(flag) => write!(f, "option `{flag}` requires a value"),
            CliError::BadNumber { flag, value } => {
                write!(f, "option `{flag}` expects a number, got `{value}`")
            }
            CliError::MemTooSmall(mb) => {
                write!(f, "--mem-mb {mb} is below the minimum of {MIN_MEM_MB} MiB")
            }
            CliError::Unknown(arg) => write!(f, "unrecognised argument `{arg}`"),
        }
    }
}

impl std::error::Error for CliError {}

/// CLI parser namespace.
pub struct Cli;

impl Cli {
    /// Parse an argument iterator (including argv[0], which is skipped).
    pub fn parse<'a, I>(args: I) -> Result<CliAction, CliError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut it = args.into_iter();
        let _program = it.next(); // skip argv[0]

        let mut kernel_path: Option<PathBuf> = None;
        let mut mem_mb = DEFAULT_MEM_MB;
        let mut cmdline = String::new();
        let mut timeout_secs = DEFAULT_TIMEOUT_SECS;
        let mut print_exit = false;
        let mut report_spawn = false;
        let mut xport_out: Option<PathBuf> = None;
        let mut xport_key_out: Option<PathBuf> = None;

        while let Some(arg) = it.next() {
            match arg {
                "-h" | "--help" => return Ok(CliAction::Help),
                "--kernel" => kernel_path = Some(PathBuf::from(req_value(&mut it, "--kernel")?)),
                "--mem-mb" => mem_mb = parse_u64(req_value(&mut it, "--mem-mb")?, "--mem-mb")?,
                "--cmdline" => cmdline = req_value(&mut it, "--cmdline")?.to_string(),
                "--timeout-secs" => {
                    timeout_secs = parse_u64(req_value(&mut it, "--timeout-secs")?, "--timeout-secs")?
                }
                "--print-exit" => print_exit = true,
                "--report-spawn" => report_spawn = true,
                "--xport-out" => {
                    xport_out = Some(PathBuf::from(req_value(&mut it, "--xport-out")?))
                }
                "--xport-key-out" => {
                    xport_key_out = Some(PathBuf::from(req_value(&mut it, "--xport-key-out")?))
                }
                other => return Err(CliError::Unknown(other.to_string())),
            }
        }

        if mem_mb < MIN_MEM_MB {
            return Err(CliError::MemTooSmall(mem_mb));
        }

        Ok(CliAction::Run(Config {
            kernel_path: kernel_path.unwrap_or_else(|| PathBuf::from(DEFAULT_KERNEL)),
            mem_bytes: mem_mb * 1024 * 1024,
            cmdline,
            timeout_secs,
            print_exit,
            report_spawn,
            xport_out,
            xport_key_out,
        }))
    }
}

/// Pull the value that must follow an option flag.
fn req_value<'a, I>(it: &mut I, flag: &'static str) -> Result<&'a str, CliError>
where
    I: Iterator<Item = &'a str>,
{
    it.next().ok_or(CliError::MissingValue(flag))
}

/// Parse a non-negative integer option.
fn parse_u64(value: &str, flag: &'static str) -> Result<u64, CliError> {
    value.parse::<u64>().map_err(|_| CliError::BadNumber {
        flag,
        value: value.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(argv: &[&str]) -> Result<CliAction, CliError> {
        Cli::parse(argv.iter().copied())
    }

    #[test]
    fn defaults_when_no_args() {
        let action = parse(&["tb-vmm"]).unwrap();
        match action {
            CliAction::Run(c) => {
                assert_eq!(c.kernel_path, PathBuf::from(DEFAULT_KERNEL));
                assert_eq!(c.mem_bytes, DEFAULT_MEM_MB * 1024 * 1024);
                assert_eq!(c.cmdline, "");
                assert_eq!(c.timeout_secs, DEFAULT_TIMEOUT_SECS);
                assert!(!c.print_exit);
                assert!(!c.report_spawn);
                assert!(c.xport_out.is_none());
                assert!(c.xport_key_out.is_none());
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn parses_all_options() {
        let action = parse(&[
            "tb-vmm",
            "--kernel",
            "/tmp/k.elf",
            "--mem-mb",
            "512",
            "--cmdline",
            "verbose=1",
            "--timeout-secs",
            "60",
            "--print-exit",
            "--report-spawn",
            "--xport-out",
            "/tmp/xport-witness.txt",
            "--xport-key-out",
            "/tmp/xport-key.hex",
        ])
        .unwrap();
        let CliAction::Run(c) = action else {
            panic!("expected Run")
        };
        assert_eq!(c.kernel_path, PathBuf::from("/tmp/k.elf"));
        assert_eq!(c.mem_bytes, 512 * 1024 * 1024);
        assert_eq!(c.cmdline, "verbose=1");
        assert_eq!(c.timeout_secs, 60);
        assert!(c.print_exit);
        assert!(c.report_spawn);
        assert_eq!(c.xport_out, Some(PathBuf::from("/tmp/xport-witness.txt")));
        assert_eq!(c.xport_key_out, Some(PathBuf::from("/tmp/xport-key.hex")));
    }

    #[test]
    fn xport_flags_require_values() {
        assert_eq!(
            parse(&["tb-vmm", "--xport-out"]).unwrap_err(),
            CliError::MissingValue("--xport-out")
        );
        assert_eq!(
            parse(&["tb-vmm", "--xport-key-out"]).unwrap_err(),
            CliError::MissingValue("--xport-key-out")
        );
    }

    #[test]
    fn report_spawn_defaults_off_and_parses() {
        let CliAction::Run(c) = parse(&["tb-vmm"]).unwrap() else {
            panic!("expected Run")
        };
        assert!(!c.report_spawn);
        let CliAction::Run(c) = parse(&["tb-vmm", "--report-spawn"]).unwrap() else {
            panic!("expected Run")
        };
        assert!(c.report_spawn);
    }

    #[test]
    fn help_flag() {
        assert_eq!(parse(&["tb-vmm", "--help"]).unwrap(), CliAction::Help);
        assert_eq!(parse(&["tb-vmm", "-h"]).unwrap(), CliAction::Help);
    }

    #[test]
    fn missing_value_is_error() {
        assert_eq!(
            parse(&["tb-vmm", "--kernel"]).unwrap_err(),
            CliError::MissingValue("--kernel")
        );
    }

    #[test]
    fn bad_number_is_error() {
        assert!(matches!(
            parse(&["tb-vmm", "--mem-mb", "lots"]).unwrap_err(),
            CliError::BadNumber { flag: "--mem-mb", .. }
        ));
    }

    #[test]
    fn mem_too_small_is_error() {
        assert_eq!(
            parse(&["tb-vmm", "--mem-mb", "1"]).unwrap_err(),
            CliError::MemTooSmall(1)
        );
    }

    #[test]
    fn unknown_flag_is_error() {
        assert_eq!(
            parse(&["tb-vmm", "--frobnicate"]).unwrap_err(),
            CliError::Unknown("--frobnicate".to_string())
        );
    }
}
