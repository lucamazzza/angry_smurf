//! ARP packet handler

use pnet_packet::arp::{ArpOperations, ArpPacket};
use serde_json::json;
use std::net::Ipv4Addr;

use crate::logger::{ev, Logger};

/// Handles ARP packets by logging their operation type and relevant information.
/// Takes the interface name, logger, and the ARP packet data.
pub fn handle_arp(iface: &str, logger: &Logger, pkt: &[u8]) {
    if let Some(arp) = ArpPacket::new(pkt) {
        let src_ip = Ipv4Addr::from(arp.get_sender_proto_addr());
        let dst_ip = Ipv4Addr::from(arp.get_target_proto_addr());
        let src_mac = arp.get_sender_hw_addr();
        let op = arp.get_operation();
        match op {
            ArpOperations::Request => {
                logger.log(ev(
                    "arp.request",
                    iface,
                    Some(&src_ip.to_string()),
                    Some(&dst_ip.to_string()),
                    json!({"src_mac": src_mac.to_string()}),
                ));
            }
            ArpOperations::Reply => {
                logger.log(ev(
                    "arp.reply",
                    iface,
                    Some(&src_ip.to_string()),
                    Some(&dst_ip.to_string()),
                    json!({"src_mac": src_mac.to_string()}),
                ));
            }
            _ => {}
        }
    }
}
