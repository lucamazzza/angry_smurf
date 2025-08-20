use dns_parser::Packet as DnsPacket;
use serde_json::json;

use crate::logger::{ev, Logger};

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
