//! Command-line interface for the angry_smurf tool.

use clap::{Parser, ValueEnum};

/// Represents the scan modes available for the angry_smurf tool.
/// - `Syn`: SYN scan mode, stealthy and fast.
/// - `Connect`: Connect scan mode, establishes a full TCP connection.
/// - `Udp`: UDP scan mode, used for scanning UDP ports.
/// - `All`: All scan modes combined, performing SYN, Connect, and UDP scans.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum ScanMode {
    Syn,
    Connect,
    Udp,
    All,
}

/// Command-line arguments for the angry_smurf tool.
/// This struct defines the options that can be passed to the tool when it is run.
/// It includes options for network interface, verbosity, output file, target IP, ports to scan,
/// delay between probes, timeout for each probe, maximum concurrent probes, and the scan mode to
/// use.
/// The `Cli` struct is derived from the `Parser` trait provided by the `clap` crate, which allows
/// for easy parsing of command-line arguments.
#[derive(Parser, Debug)]
#[command(name = "asmurf", about = "Stealthy Network Reconnaissance Tool")]
pub struct Cli {
    #[arg(short, long, default_value="eth0", help = "Network interface to use")]
    pub interface: String,
    #[arg(short, long, help = "Enable verbose output")]
    pub verbose: bool,
    #[arg(short, long, help = "Output buffer file [default: stdout]")]
    pub output: Option<String>,
    #[arg(short, long, help = "Target IP address or hostname")]
    pub target: Option<String>,
    #[arg(long, default_value = "22, 80, 443", help = "Comma-separated list of ports to scan")]
    pub ports: String,
    #[arg(long, default_value_t = 500, help = "Delay between probes in milliseconds")]
    pub delay: u64,
    #[arg(long, default_value_t = 200, help = "Timeout for each probe in milliseconds")]
    pub jitter: u64,
    #[arg(long, default_value_t = 1, help = "Maximum number of concurrent probes")]
    pub max_inflight: usize,
    #[arg(long, value_enum, default_value_t = ScanMode::All, help = "Scan mode: syn, connect, udp, or all")]
    pub scan_mode: ScanMode,
}
