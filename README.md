# Angry Smurf

> [!NOTE]
> Currently Work in Progress

angry_smurf is a small, fast network probing tool written in Rust. It can:
- Send ICMP Echo (ping) probes.
- Perform TCP connect scans (using the OS TCP stack).
- Perform TCP SYN “half-open” probes using raw packets.

It’s designed to emit structured, line-oriented JSON logs so you can pipe results into your tooling easily.

> Note: Raw TCP SYN probing requires elevated privileges and slightly different OS behaviors. See “Permissions and OS notes” below.

---

## Features

- ICMP Echo probe (ping) per target
- TCP connect scan — simple, portable open/closed detection
- TCP SYN probe — fast and low-overhead for open/closed (SYN-ACK/RST) detection
- Per-probe pacing with delay and jitter
- Structured JSON logging for all events
- Interface selection and correct IPv4 source selection

---

## Build

Prerequisites:
- Rust (stable)
- libpcap (recommended on macOS/BSD for reliable receive paths)
  - macOS: comes with the system (install Xcode Command Line Tools if needed)
  - Debian/Ubuntu: `sudo apt-get install libpcap-dev`
  - Fedora: `sudo dnf install libpcap-devel`

Build release binary:
```bash
cargo build --release
```

---

## Permissions and OS notes

Raw packet I/O typically requires elevated privileges.

- Linux:
  - Run as root, or grant capabilities:
    ```bash
    sudo setcap cap_net_raw,cap_net_admin=eip target/release/angry_smurf
    ```
- macOS/BSD:
  - Raw TCP at Layer 4 is restricted; angry_smurf crafts full IPv4+TCP and/or uses pcap for receive paths.
  - Run with `sudo` to access BPF devices for capture.

Network/security devices (e.g., home routers, WAFs) may drop crafted packets or rate-limit management ports. Test first on a host you control on the same LAN.

---

## Usage

The project emits JSON logs per event. A typical flow is:
1) Resolve the IPv4 of the chosen interface (source IP).
2) Probe a set of ports using TCP connect or TCP SYN.
3) Optionally ping with ICMP Echo.

Because CLI flags may evolve, run the binary with `--help` to see the current arguments:
```bash
target/release/angry_smurf --help
```

Example run (adjust flags to match your binary’s help output):
```bash
# Example: probe a target on interface en1
sudo target/release/angry_smurf \
  --iface en1 \
  --target 192.168.1.1 \
  --ports 22,80,443 \
  --delay-ms 100 \
  --jitter-ms 50
```

You can pipe JSON output to jq:
```bash
sudo target/release/angry_smurf ... | jq .
```

---

## Example output

ICMP Echo reply:
```json
{"ts":"2025-08-22T14:35:10Z","kind":"icmp.reply","iface":"en1","src":"192.168.1.121","dst":"192.168.1.10","details":{"id":4919,"seq":1}}
```

TCP connect scan:
```json
{"ts":"2025-08-22T14:35:12Z","kind":"tcp.open","iface":"en1","src":"192.168.1.121","dst":"192.168.1.10:22","details":{"note":"TCP port open","port":22}}
{"ts":"2025-08-22T14:35:13Z","kind":"tcp.closed","iface":"en1","src":"192.168.1.121","dst":"192.168.1.10:81","details":{"note":"TCP port closed","port":81}}
```

TCP SYN probe:
```json
{"ts":"2025-08-22T14:35:15Z","kind":"tcp.synack","iface":"en1","src":"192.168.1.121","dst":"192.168.1.10","details":{"port":22,"note":"SYN-ACK received"}}
{"ts":"2025-08-22T14:35:17Z","kind":"tcp.closed","iface":"en1","src":"192.168.1.121","dst":"192.168.1.10","details":{"port":81,"note":"RST received, port closed"}}
{"ts":"2025-08-22T14:35:19Z","kind":"tcp.timeout","iface":"en1","src":"192.168.1.121","dst":"192.168.1.10","details":{"port":443,"note":"no response"}}
```

Field meanings:
- ts: ISO8601 timestamp (UTC)
- kind: event type (icmp.reply, icmp.timeout, tcp.open, tcp.closed, tcp.synack, tcp.timeout, tcp.error)
- iface: network interface used
- src: local IPv4
- dst: target IPv4 (or host:port for connect scan)
- details: event-specific fields (port, notes, errors)

---

## How it works (high level)

- ICMP: Crafts and sends Echo Request, looks for Echo Reply from the target.
- TCP connect scan: Uses `tokio::net::TcpStream::connect` for open/closed detection, fully portable.
- TCP SYN probe: Crafts a minimal TCP SYN (20-byte TCP) with correct checksum and data offset, sends via Layer 3 (IPv4). Replies are detected as:
  - SYN-ACK => open
  - RST => closed
  - No reply => filtered/timeout

On macOS/BSD, receiving SYN-ACK/RST reliably is done via a BPF filter (pcap).

---

## Verification

If you see only timeouts, verify with tcpdump that packets are leaving and replies are visible:

```bash
# Replace en1 and target IP accordingly
sudo tcpdump -ni en1 "host 192.168.1.10 and tcp and (tcp[tcpflags] & (tcp-syn|tcp-ack|tcp-rst) != 0)"
```

You should see:
- Your SYN going out (S)
- A SYN-ACK (SA) or RST (R) coming back, if the target responds

---

## Troubleshooting

- Must run with privileges (root, or capabilities on Linux).
- Ensure the source IP (from the chosen interface) is used for checksum and sending, not the target IP.
- Firewalls or ACLs may drop crafted SYNs; try a known-open host/port on your LAN first.
- Wi‑Fi interfaces on macOS sometimes need immediate mode BPF; running as root generally enables this via pcap.
- If using a VPN or virtual interface, reply routing may differ; test on a direct LAN link first.

---

## Development

- Language: Rust + Tokio
- Packet crafting/capture: pnet (and pcap for capture on macOS/BSD)
- Logging: line-oriented JSON to stdout

Build and run tests:
```bash
cargo build
cargo test
```

Run with increased verbosity by piping to `jq` or your preferred log processor.

---

## Roadmap ideas

- Parallel multi-target scanning
- Source port randomization and correlation across higher concurrency
- IPv6 support
- Service banner grabs (optionally after detecting open with SYN)
- Single shared capture per interface with demultiplexing for better performance
- Config file (TOML/JSON) support

---

## Disclaimer

Use responsibly and only on networks/hosts you own or are authorized to test. The authors and contributors are not responsible for misuse or damage.

---

## License

[Choose a license and place it in LICENSE]
