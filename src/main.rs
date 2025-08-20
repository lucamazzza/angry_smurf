mod cli;
mod logger;
mod recon;
mod sniff;
mod targets;

use clap::Parser;
use cli::{Cli, ScanMode};
use recon::{
    scanner::{icmp_probe, iface_ipv4, tcp_connect_scan, tcp_syn_probe, ScanConfig},
    scheduler::{schedule, SchedulerConfig},
};
use sniff::start_capture;
use std::{net::Ipv4Addr, path::PathBuf, sync::Arc};

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    let out_path: Option<PathBuf> = args.output.clone().map(Into::into);
    let logger = Arc::new(logger::Logger::new(out_path).expect("Failed to initialize logger"));

    let iface_capture = args.interface.clone();
    let logger_capture = logger.as_ref().clone();
    let _capture_handle = tokio::spawn(async move {
        let _ = start_capture(iface_capture, args.verbose, logger_capture).await;
    });

    let ports: Vec<u16> = args
        .ports
        .split(',')
        .filter_map(|p| p.trim().parse().ok())
        .collect();
    let cfg = Arc::new(ScanConfig {
        iface: args.interface.clone(),
        delay_ms: args.delay,
        jitter_ms: args.jitter,
        ports,
    });

    let targets: Vec<Ipv4Addr> = match &args.target {
        Some(spec) => match targets::parse_targets(spec) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("Error parsing targets: {}", e);
                return;
            }
        },
        None => {
            eprintln!("No target specified. Use --target <IP/CIDR/@file> to specify targets.");
            return;
        }
    };

    let scheduler_cfg = SchedulerConfig::new(args.delay, args.jitter, args.max_inflight);
    let logger_all = logger.clone();
    let cfg_all = cfg.clone();
    let mode = args.scan_mode;

    schedule(targets, scheduler_cfg, move |target_ip| {
        let logger = logger_all.clone();
        let cfg_arc = cfg_all.clone();
        async move {
            let iface: String = cfg_arc.iface.clone();
            let logger_own = logger.as_ref().clone();
            let Some(sip) = iface_ipv4(&iface) else {
                eprintln!(
                    "[!] Failed to get IPv4 address for interface '{}': skipping SYN probes",
                    iface
                );
                return;
            };
            eprintln!("[*] Scheduled probes (source ip: {})", sip);
            match mode {
                ScanMode::All => {
                    icmp_probe(&logger_own, cfg_arc.as_ref(), target_ip).await;
                    tcp_connect_scan(&logger_own, cfg_arc.as_ref(), target_ip).await;
                    tcp_syn_probe(&cfg_arc, sip, std::net::IpAddr::V4(target_ip), &logger_own)
                        .await;
                }
                ScanMode::Connect => {
                    tcp_connect_scan(&logger_own, cfg_arc.as_ref(), target_ip).await;
                }
                ScanMode::Syn => {
                    tcp_syn_probe(&cfg_arc, sip, std::net::IpAddr::V4(target_ip), &logger_own)
                        .await;
                }
                ScanMode::Udp => {
                    // Placeholder for UDP scan logic
                    eprintln!("UDP scan mode is not implemented yet.");
                }
            }
        }
    })
    .await
}
