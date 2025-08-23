use std::{
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use pcap::Capture;
use pnet::{datalink, ipnetwork::IpNetwork, transport::transport_channel};
use pnet_packet::{
    icmp::{echo_request, IcmpTypes},
    ip::IpNextHeaderProtocols::{self},
    ipv4::{checksum as ipv4_checksum, Ipv4Packet, MutableIpv4Packet},
    tcp::{ipv4_checksum as tcp_ipv4_checksum, MutableTcpPacket, TcpFlags},
    Packet,
};

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

pub fn build_echo_request<'a>(buf: &'a mut [u8]) -> echo_request::MutableEchoRequestPacket<'a> {
    let mut echo = echo_request::MutableEchoRequestPacket::new(buf).unwrap();
    echo.set_icmp_type(IcmpTypes::EchoRequest);
    echo.set_identifier(0x1337);
    echo.set_sequence_number(1);
    let csum = pnet::packet::util::checksum(echo.packet(), 1);
    echo.set_checksum(csum);
    echo
}

fn _build_ipv4_tcp_syn<'a>(
    buf: &'a mut [u8],
    sip: std::net::Ipv4Addr,
    dip: std::net::Ipv4Addr,
    sport: u16,
    dport: u16,
) -> pnet::packet::ipv4::MutableIpv4Packet<'a> {
    assert!(buf.len() >= 40);
    let (ip_hdr, rest) = buf.split_at_mut(20);
    let tcp_hdr = &mut rest[..20];
    ip_hdr.fill(0);
    tcp_hdr.fill(0);
    {
        tcp_hdr[12] = 0x50;
        let mut tcp = MutableTcpPacket::new(tcp_hdr).unwrap();
        tcp.set_source(sport);
        tcp.set_destination(dport);
        tcp.set_sequence(0);
        tcp.set_flags(TcpFlags::SYN);
        tcp.set_window(64240);
        tcp.set_data_offset(5);
        tcp.set_checksum(0);
        let t_csum = tcp_ipv4_checksum(&tcp.to_immutable(), &sip, &dip);
        tcp.set_checksum(t_csum);
    }
    ip_hdr[0] = 0x45;
    let mut ip = MutableIpv4Packet::new(ip_hdr).unwrap();
    ip.set_total_length(40);
    ip.set_ttl(64);
    ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip.set_source(sip);
    ip.set_destination(dip);
    ip.set_checksum(0);
    let ip_csum = ipv4_checksum(&ip.to_immutable());
    ip.set_checksum(ip_csum);
    MutableIpv4Packet::new(&mut buf[..40]).unwrap()
}

fn build_ipv4_tcp_syn_bytes_owned(sip: Ipv4Addr, dip: Ipv4Addr, sport: u16, dport: u16) -> Vec<u8> {
    let mut tcp_hdr = [0u8; 20];
    {
        tcp_hdr[12] = 0x50;
        let mut tcp = MutableTcpPacket::new(&mut tcp_hdr[..]).unwrap();
        tcp.set_source(sport);
        tcp.set_destination(dport);
        tcp.set_sequence(0);
        tcp.set_flags(TcpFlags::SYN);
        tcp.set_window(64240);
        tcp.set_data_offset(5);
        tcp.set_checksum(0);
        let csum = tcp_ipv4_checksum(&tcp.to_immutable(), &sip, &dip);
        tcp.set_checksum(csum);
    }
    let mut ip_hdr = [0u8; 20];
    {
        ip_hdr[0] = 0x45;
        let mut ip = MutableIpv4Packet::new(&mut ip_hdr[..]).unwrap();
        ip.set_total_length(40);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(sip);
        ip.set_destination(dip);
        ip.set_checksum(0);
        let csum = ipv4_checksum(&ip.to_immutable());
        ip.set_checksum(csum);
    }

    let mut bytes = Vec::with_capacity(40);
    bytes.extend_from_slice(&ip_hdr);
    bytes.extend_from_slice(&tcp_hdr);
    bytes
}

fn _debug_dump_ipv4_tcp(buf: &[u8]) {
    if buf.len() < 40 {
        eprintln!("[!] Buffer too small for IPv4+TCP");
        return;
    }
    let ip0 = &buf[0];
    let tcp_off_byte = buf[20 + 12];
    eprintln!("[+] Debug dump of IPv4+TCP packet:");
    eprintln!(
        "\t IP[0]=0x{:02x} (ver={}, ihl={})\n\tTCP[12]=0x{:02x} (data_offs={})",
        ip0,
        ip0 >> 4,
        ip0 & 0x0f,
        tcp_off_byte,
        tcp_off_byte >> 4
    );
    eprint!("IP: ");
    for b in &buf[0..20] {
        eprint!("{:02x} ", b);
    }
    eprintln!();
    eprint!("TCP: ");
    for b in &buf[20..40] {
        eprint!("{:02x} ", b);
    }
    eprintln!();
}

pub fn wait_for_syn_reply_pcap(
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

pub fn send_one_syn(
    sip: Ipv4Addr,
    dip: Ipv4Addr,
    sport: u16,
    dport: u16,
) -> Result<(), std::io::Error> {
    let (mut tx, _) = transport_channel(
        64 * 1024,
        pnet::transport::TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp),
    )?;
    let bytes = build_ipv4_tcp_syn_bytes_owned(sip, dip, sport, dport);
    assert_eq!(bytes.len(), 40, "built length != 40");
    let pkt = Ipv4Packet::new(&bytes[..]).expect("valid IPv4 packet");
    assert_eq!(pkt.get_total_length(), 40, "IPv4 total length != 40");
    let sent = tx.send_to(pkt, std::net::IpAddr::V4(dip))?;
    assert_eq!(
        sent, 40,
        "kernel reported sending {} bytes, expected 40",
        sent
    );
    Ok(())
}
