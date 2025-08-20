use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

use pcap::Capture;
use pnet::{
    datalink,
    ipnetwork::IpNetwork,
    transport::{
        icmp_packet_iter, transport_channel, TransportChannelType::Layer4, TransportProtocol,
    },
};
use pnet_packet::{
    icmp::{echo_request, IcmpTypes},
    ip::IpNextHeaderProtocols::{self},
    ipv4::{checksum as ipv4_checksum, MutableIpv4Packet},
    tcp::{ipv4_checksum as tcp_ipv4_checksum, MutableTcpPacket, TcpFlags},
    Packet,
};
use rand::{thread_rng, Rng};
use serde_json::json;
use tokio::time::sleep;

use crate::logger::{ev, Logger};

pub struct ScanConfig {
    pub iface: String,
    pub delay_ms: u64,
    pub jitter_ms: u64,
    pub ports: Vec<u16>,
}

pub fn iface_ipv4(name: &str) -> Option<Ipv4Addr> {
    let iface = datalink::interfaces()
        .into_iter()
        .find(|i| i.name == name)?;
    for ip in iface.ips {
        if let IpNetwork::V4(v4) = ip {
            return Some(v4.ip());
        }
    }
    None
}

fn build_echo_request<'a>(buf: &'a mut [u8]) -> echo_request::MutableEchoRequestPacket<'a> {
    let mut echo = echo_request::MutableEchoRequestPacket::new(buf).unwrap();
    echo.set_icmp_type(IcmpTypes::EchoRequest);
    echo.set_identifier(0x1337);
    echo.set_sequence_number(1);
    let csum = pnet::packet::util::checksum(echo.packet(), 1);
    echo.set_checksum(csum);
    echo
}

fn build_ipv4_tcp_syn<'a>(
    buf: &'a mut [u8],
    sip: Ipv4Addr,
    dip: Ipv4Addr,
    sport: u16,
    dport: u16,
) -> MutableIpv4Packet<'a> {
    let total_len = 20 + 20;
    assert!(buf.len() >= total_len, "buffer too small for IPv4+TCP");
    {
        let tcp_buf = &mut buf[20..total_len];
        let mut tcp = MutableTcpPacket::new(tcp_buf).unwrap();
        tcp.set_source(sport);
        tcp.set_destination(dport);
        tcp.set_sequence(0);
        tcp.set_flags(TcpFlags::SYN);
        tcp.set_window(65535);
        tcp.set_data_offset(5);
        tcp.set_checksum(tcp_ipv4_checksum(&tcp.to_immutable(), &sip, &dip));
    }
    let mut ip = MutableIpv4Packet::new(&mut buf[..total_len]).expect("Buffer too small");
    ip.set_version(4);
    ip.set_header_length(5);
    ip.set_total_length(total_len as u16);
    ip.set_ttl(64);
    ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip.set_source(sip);
    ip.set_destination(dip);
    ip.set_checksum(ipv4_checksum(&ip.to_immutable()));
    ip
}

fn wait_for_syn_reply_pcap(
    iface: &str,
    target: Ipv4Addr,
    sport: u16,
    overall: Duration,
) -> Result<Option<&'static str>, pcap::Error> {
    let mut cap = Capture::from_device(iface)?
        .timeout(500) // ms
        .immediate_mode(true)
        .open()?;
    let start = Instant::now();
    let synack_filter = format!(
        "ip and tcp and src host {} and dst port {} and tcp[13] & 0x12 = 0x12",
        target, sport
    );
    cap.filter(&synack_filter, true)?;
    while start.elapsed() < overall {
        match cap.next_packet() {
            Ok(_) => return Ok(Some("SYNACK")),
            Err(pcap::Error::TimeoutExpired) => {
                if start.elapsed() >= overall {
                    break;
                }
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    let remaining = overall
        .checked_sub(start.elapsed())
        .unwrap_or_else(|| Duration::from_millis(0));
    if remaining.is_zero() {
        return Ok(None);
    }
    let rst_filter = format!(
        "ip and tcp and src host {} and dst port {} and tcp[13] & 0x04 = 0x04",
        target, sport
    );
    cap.filter(&rst_filter, true)?;
    let start_rst = Instant::now();
    while start_rst.elapsed() < remaining {
        match cap.next_packet() {
            Ok(_) => return Ok(Some("RST")),
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => return Err(e),
        }
    }

    Ok(None)
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
        let protocol = Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
        let (mut tx, mut _rx) = match transport_channel(4096, protocol) {
            Ok(v) => v,
            Err(e) => {
                logger.log(ev(
                    "tcp.error",
                    &cfg.iface,
                    Some(&sip.to_string()),
                    Some(&target.to_string()),
                    json!({ "error": e.to_string() }),
                ));
                continue;
            }
        };
        let sport: u16 = thread_rng().gen_range(1024..65535);
        let mut buf = [0u8; 64];
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
        let tcp = build_ipv4_tcp_syn(&mut buf, sip, target_as_ipv4addr, sport, port);
        if let Err(e) = tx.send_to(tcp, target) {
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
