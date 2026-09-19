# Getting Started with multiprobe

## What you get

multiprobe is a Rust library for multi-protocol network probing. It lets you:

- Measure TCP, UDP, and ICMP reachability with per-direction timing
- Run Paris Traceroute (flow-consistent paths, ECMP detection)
- Measure path asymmetry (forward vs. reverse latency)
- Detect protocol divergence (ICMP and TCP/UDP taking different paths)
- Correlate divergence with BGP topology to classify root causes (ABDS score)
- Probe TLS handshake timing (DNS + TCP + TLS separately)

## Requirements

Most features require elevated privileges (ICMP raw sockets):

| Feature | Requires root/CAP_NET_RAW |
|---------|--------------------------|
| TCP probe | No |
| UDP probe | No |
| ICMP probe | **Yes** |
| Traceroute | **Yes** (ICMP TTL) |
| Paris traceroute (UDP/ICMP/TCP) | **Yes** |
| Paris traceroute (UdpUnprivileged) | **No — Linux only** |
| BGP correlation | **Yes** (via traceroute) |
| TLS probe | No |
| Bidirectional | No (TCP-based) |

### Running without root on Linux

Use `ParisMode::UdpUnprivileged` — it uses `IP_RECVERR` + `MSG_ERRQUEUE`
so ICMP TTL-exceeded replies arrive on the socket's error queue without
needing a raw socket:

```bash
cargo run --example unprivileged_traceroute 8.8.8.8   # no sudo!
```

On Linux, grant CAP_NET_RAW without full root:
```bash
sudo setcap cap_net_raw+ep target/debug/my-binary
```

On macOS, use `sudo` or add your user to the `wheel` group.

**Note: IPv4 only.** IPv6 support is not yet implemented.

## Installation

```toml
[dependencies]
multiprobe = "0.5"
tokio = { version = "1", features = ["full"] }
```

## Quick examples

```bash
# Basic TCP/UDP probe
cargo run --example basic_probes google.com

# Traceroute with Paris algorithm
sudo cargo run --example paris_traceroute 8.8.8.8

# BGP correlation + ABDS score (the library's core novel contribution)
sudo cargo run --example bgp_correlation 8.8.8.8

# Path latency analytics
sudo cargo run --example latency_analysis 8.8.8.8

# TLS handshake timing breakdown
cargo run --example tls_analysis google.com

# Bidirectional path asymmetry (needs a server)
cargo run --example bidirectional -- server 0.0.0.0:33435   # on machine B
cargo run --example bidirectional <machine-B-ip>             # on machine A
```

## Running the test suite

```bash
# Fast tests (no network/root required)
cargo test

# Network tests (require DNS, internet access)
cargo test -- --ignored

# With coverage
cargo test -- --test-threads=1
```
