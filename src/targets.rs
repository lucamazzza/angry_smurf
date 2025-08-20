use std::{fs::File, io::{self, BufRead, BufReader}, net::Ipv4Addr, path::Path, str::FromStr};

use ipnet::Ipv4Net;

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
