//! DNS packet handler

use dns_parser::Packet as DnsPacket;
use serde_json::json;

use crate::logger::{ev, Logger};

/// Handles DNS packets by parsing them and logging queries and answers.
/// This function expects the DNS packet to be in the form of a byte slice (`pkt`),
/// and it logs the DNS queries and answers using the provided `logger`.
/// `iface` is the network interface name, `sip` is the source IP address,
/// `dip` is the destination IP address.
pub fn handle_dns(iface: &str, logger: &Logger, pkt: &[u8], sip: &str, dip: &str) {
    if let Ok(dns) = DnsPacket::parse(pkt) {
        for q in dns.questions {
            logger.log(ev(
                "dns.query",
                iface,
                Some(&sip.to_string()),
                Some(&dip.to_string()),
                json!({
                    "qname": q.qname.to_string(),
                    "qtype": format!("{:?}", q.qtype),
                }),
            ));
        }
        for a in dns.answers {
            logger.log(ev(
                "dns.answer",
                iface,
                Some(&sip.to_string()),
                Some(&dip.to_string()),
                json!({
                    "aname": a.name.to_string(),
                    "data": format!("{:?}", a.data),
                }),
            ));
        }
    }
}
