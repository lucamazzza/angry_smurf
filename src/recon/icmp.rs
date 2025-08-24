//! ICMP packet handler

use pnet_packet::{
    icmp::{IcmpPacket, IcmpTypes},
    Packet,
};
use serde_json::json;

use crate::logger::{ev, Logger};

/// Handles ICMP packets by logging their type and relevant information.
/// Takes the interface name, logger, and the IP header containing the ICMP packet.
pub fn handle_icmp(iface: &str, logger: &Logger, ip_header: &pnet_packet::ipv4::Ipv4Packet) {
    if let Some(icmp) = IcmpPacket::new(ip_header.payload()) {
        let src_ip = ip_header.get_source();
        let dst_ip = ip_header.get_destination();
        match icmp.get_icmp_type() {
            IcmpTypes::EchoRequest => {
                logger.log(ev(
                    "icmp.echo_request",
                    iface,
                    Some(&src_ip.to_string()),
                    Some(&dst_ip.to_string()),
                    json!({ "len": icmp.packet().len() }),
                ));
            }
            IcmpTypes::EchoReply => {
                logger.log(ev(
                    "icmp.echo_reply",
                    iface,
                    Some(&src_ip.to_string()),
                    Some(&dst_ip.to_string()),
                    json!({ "len": icmp.packet().len() }),
                ));
            }
            other => {
                logger.log(ev(
                    "icmp.other",
                    iface,
                    Some(&src_ip.to_string()),
                    Some(&dst_ip.to_string()),
                    json!({
                        "type": format!("{:?}", other),
                    }),
                ));
            }
        }
    }
}
