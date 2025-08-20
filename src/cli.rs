use clap::{Parser, ValueEnum};

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum ScanMode {
    Syn,
    Connect,
    Udp,
    All,
}

#[derive(Parser, Debug)]
#[command(name = "asmurf", about = "Stealthy Network Reconnaissance Tool")]
pub struct Cli {
    #[arg(short, long, default_value="eth0", help = "Network interface to use")]
    pub interface: String,
    #[arg(short, long, help = "Enable verbose output")]
    pub verbose: bool,
    #[arg(short, long, help = "Output buffer file [default: stdout]")]
    pub output: Option<String>,
    #[arg(long, help = "Target IP address or hostname")]
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
