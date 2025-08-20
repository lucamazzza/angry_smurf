use pcap::{Capture, Device};
use pnet_packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    udp::UdpPacket,
    Packet,
};
use std::error::Error;

use crate::{
    logger::Logger,
    recon::{arp, dns, icmp},
};

pub async fn start_capture(
    interface: String,
    verbose: bool,
    logger: Logger,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let dev = Device::list()?
        .into_iter()
        .find(|d| d.name == interface)
        .ok_or_else(|| format!("[!] Interface '{}' not found", interface))?;
    if verbose {
        eprintln!("[*] Starting capture on interface: '{}'", dev.name);
    }
    let mut cap = Capture::from_device(dev)?
        .promisc(true)
        .snaplen(65535)
        .open()?;
    while let Ok(packet) = cap.next_packet() {
        if let Some(eth) = EthernetPacket::new(packet.data) {
            match eth.get_ethertype() {
                EtherTypes::Arp => {
                    arp::handle_arp(interface.as_str(), &logger, eth.payload());
                }
                EtherTypes::Ipv4 => {
                    if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                        match ip.get_next_level_protocol() {
                            IpNextHeaderProtocols::Icmp => {
                                icmp::handle_icmp(interface.as_str(), &logger, &ip);
                            }
                            IpNextHeaderProtocols::Udp => {
                                if let Some(udp) = UdpPacket::new(ip.payload()) {
                                    if udp.get_source() == 53 || udp.get_destination() == 53 {
                                        let sip = ip.get_source().to_string();
                                        let dip = ip.get_destination().to_string();
                                        dns::handle_dns(interface.as_str(), &logger, &udp.payload(), &sip, &dip);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}
