use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use pnet::transport::{
    icmp_packet_iter, transport_channel, TransportChannelType::Layer4, TransportProtocol,
};
use pnet_packet::{
    icmp::IcmpTypes,
    ip::IpNextHeaderProtocols::{self},
};
use rand::{thread_rng, Rng};
use serde_json::json;
use tokio::time::sleep;

use crate::logger::{ev, Logger};
use crate::recon::net::{build_echo_request, wait_for_syn_reply_pcap};

use super::net::send_one_syn;

pub struct ScanConfig {
    pub iface: String,
    pub delay_ms: u64,
    pub jitter_ms: u64,
    pub ports: Vec<u16>,
}

pub async fn icmp_probe(logger: &Logger, cfg: &ScanConfig, target: Ipv4Addr) {
    let protocol = Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp));
    let (mut tx, mut rx) = match transport_channel(1024, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            eprintln!("[!] Failed to create transport channel: {}", e);
            return;
        }
    };
    let mut buf = [0u8; 64];
    let echo = build_echo_request(&mut buf);

    match tx.send_to(echo, std::net::IpAddr::V4(target)) {
        Ok(_) => {
            logger.log(ev(
                "icmp.probe",
                &cfg.iface,
                None,
                Some(&target.to_string()),
                json!({ "id": 0x1337, "seq": 1 }),
            ));
        }
        Err(e) => {
            eprintln!("[!] Failed to send ICMP probe: {}", e);
        }
    }
    let mut iter = icmp_packet_iter(&mut rx);
    let timeout = Duration::from_secs(2);
    let mut got_reply = false;
    let start = tokio::time::Instant::now();
    while start.elapsed() < timeout {
        match iter.next() {
            Ok((packet, addr)) => {
                if packet.get_icmp_type() == IcmpTypes::EchoReply {
                    logger.log(ev(
                        "icmp.reply",
                        &cfg.iface,
                        None,
                        Some(&addr.to_string()),
                        json!({ "id": 0x1337, "seq": 1 }),
                    ));
                    got_reply = true;
                    break;
                }
            }
            Err(e) => {
                eprintln!("[!] Error reading ICMP packet: {}", e);
                break;
            }
        }
    }
    if !got_reply {
        logger.log(ev(
            "icmp.timeout",
            &cfg.iface,
            None,
            Some(&target.to_string()),
            json!({ "note": "no reply" }),
        ));
    }
    let jitter = thread_rng().gen_range(0..cfg.jitter_ms);
    sleep(Duration::from_millis(cfg.delay_ms + jitter)).await;
}

pub async fn tcp_connect_scan(logger: &Logger, cfg: &ScanConfig, target: Ipv4Addr) {
    for port in &cfg.ports {
        let addr = SocketAddr::new(target.into(), *port);
        let jitter = thread_rng().gen_range(0..cfg.jitter_ms);
        match tokio::net::TcpStream::connect(addr).await {
            Ok(_) => {
                logger.log(ev(
                    "tcp.open",
                    &cfg.iface,
                    None,
                    Some(&addr.to_string()),
                    json!({"note": "TCP port open", "port": port}),
                ));
            }
            Err(_) => {
                logger.log(ev(
                    "tcp.closed",
                    &cfg.iface,
                    None,
                    Some(&addr.to_string()),
                    json!({"note": "TCP port closed", "port": port}),
                ));
            }
        }
        sleep(Duration::from_millis(cfg.delay_ms + jitter)).await;
    }
}

pub async fn tcp_syn_probe(cfg: &ScanConfig, sip: Ipv4Addr, target: IpAddr, logger: &Logger) {
    for port in cfg.ports.iter().cloned() {
        let sport: u16 = thread_rng().gen_range(1024..65535);
        let target_as_ipv4addr = match target {
            IpAddr::V4(ip) => Ipv4Addr::from(ip),
            IpAddr::V6(_) => {
                logger.log(ev(
                    "tcp.error",
                    &cfg.iface,
                    Some(&sip.to_string()),
                    Some(&target.to_string()),
                    json!({ "error": "IPv6 not supported for TCP SYN probes" }),
                ));
                continue;
            }
        };
        if let Err(e) = send_one_syn(sip, target_as_ipv4addr, sport, port) {
            logger.log(ev(
                "tcp.error",
                &cfg.iface,
                Some(&sip.to_string()),
                Some(&target.to_string()),
                json!({ "error": e.to_string() }),
            ));
            continue;
        };
        match wait_for_syn_reply_pcap(
            &cfg.iface,
            target_as_ipv4addr,
            sport,
            Duration::from_secs(2),
        ) {
            Ok(Some("SYNACK")) => {
                logger.log(ev(
                    "tcp.synack",
                    &cfg.iface,
                    Some(&sip.to_string()),
                    Some(&target.to_string()),
                    json!({ "port": port }),
                ));
            }
            Ok(Some("RST")) => {
                logger.log(ev(
                    "tcp.rst",
                    &cfg.iface,
                    Some(&sip.to_string()),
                    Some(&target.to_string()),
                    json!({ "port": port }),
                ));
            }
            Ok(Some(_)) => {
                logger.log(ev(
                    "tcp.unknown",
                    &cfg.iface,
                    Some(&sip.to_string()),
                    Some(&target.to_string()),
                    json!({ "port": port, "note": "unexpected TCP flags" }),
                ));
            }
            Ok(None) => {
                logger.log(ev(
                    "tcp.timeout",
                    &cfg.iface,
                    Some(&sip.to_string()),
                    Some(&target.to_string()),
                    json!({ "port": port, "note": "no reply" }),
                ));
            }
            Err(e) => {
                logger.log(ev(
                    "tcp.error",
                    &cfg.iface,
                    Some(&sip.to_string()),
                    Some(&target.to_string()),
                    json!({ "error": e.to_string() }),
                ));
            }
        }
    }
}
