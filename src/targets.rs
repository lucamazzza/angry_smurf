//! Parses target specifications for IPv4 addresses or CIDR ranges, including reading from a file.

use std::{fs::File, io::{self, BufRead, BufReader}, net::Ipv4Addr, path::Path, str::FromStr};

use ipnet::Ipv4Net;

/// Parses a target specification string into a vector of IPv4 addresses.
/// The specification can be a single IPv4 address, a CIDR range, or a file prefixed with `@`.
pub fn parse_targets(spec: &str) -> io::Result<Vec<Ipv4Addr>> {
    if let Some(file) = spec.strip_prefix('@') {
        return read_targets_file(file);
    }
    if let Ok(ip) = Ipv4Addr::from_str(spec) {
        return Ok(vec![ip]);
    }
    if let Ok(net) = Ipv4Net::from_str(spec) {
        return Ok(net.hosts().collect());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("Invalid target specification: {}. Use IPv4, CIDR or @file", spec),
    ))
}

/// Reads a file containing target specifications, where each line can be an IPv4 address,
/// CIDR range, or a comment (starting with `#`).
fn read_targets_file<P: AsRef<Path>>(path: P) -> io::Result<Vec<Ipv4Addr>> {
    let f = File::open(path)?;
    let rdr = BufReader::new(f);
    let mut out = Vec::new();
    for line in rdr.lines() {
        let line = line?;
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        if let Ok(ip) = s.parse::<Ipv4Addr>() {
            out.push(ip);
            continue;
        }
        if let Ok(net) = s.parse::<Ipv4Net>() {
            out.extend(net.hosts());
            continue;
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid target specification: {}", s),
        ));
    }
    Ok(out)
}
