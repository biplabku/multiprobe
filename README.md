# multiprobe

[![Crates.io](https://img.shields.io/crates/v/multiprobe.svg)](https://crates.io/crates/multiprobe)
[![Documentation](https://docs.rs/multiprobe/badge.svg)](https://docs.rs/multiprobe)
[![License](https://img.shields.io/crates/l/multiprobe.svg)](LICENSE)

Enterprise-grade multi-protocol network probing library for Rust with **Protocol Divergence Localization**, Paris Traceroute, path analytics, MTU discovery, bufferbloat detection, and TLS analysis.

## Why multiprobe?

- **Paris Traceroute** - ECMP-aware path tracing integrated into a unified multi-protocol probing library
- **Protocol Divergence Localization** - Find WHERE in the path protocols behave differently (NEW)
- **Comprehensive Analytics** - Jitter, MTU, bufferbloat, reordering in one crate
- **Protocol Differential Score** - Novel metric for cross-protocol path analysis
- **Production Ready** - 100+ tests, zero unsafe in public API

## Features

### Protocol Probes
| Probe | Description | Privileges |
|-------|-------------|------------|
| TCP | Connect probes with timing breakdown | None |
| UDP | Packet probes with response detection | None |
| ICMP | Echo requests with RTT measurement | CAP_NET_RAW |
| TLS | Handshake timing, cipher, version analysis | None |

### Path Discovery
| Feature | Description |
|---------|-------------|
| Traceroute | Standard hop-by-hop path discovery |
| Paris Traceroute | ECMP-aware traceroute (maintains flow consistency) |
| Multi-path Discovery | Find all paths through load balancers |
| Load Balancing Detection | Identify per-flow vs per-packet ECMP |
| **Protocol Divergence** | Find which hop causes protocol-specific failures (NEW) |

### Path Analytics
| Metric | Description |
|--------|-------------|
| Latency Stats | min/max/mean/median/p95/p99/jitter |
| Path MTU | Binary search MTU discovery |
| Bufferbloat | Latency degradation under load (A-F grading) |
| Packet Reordering | Out-of-order delivery detection |
| **Bidirectional** | Forward/reverse path asymmetry detection (NEW) |

### Classification
| Feature | Description |
|---------|-------------|
| Path Fingerprint | Stable hashes for path comparison |
| Protocol Differential Score | Cross-protocol behavior analysis |
| Network Behavior | ICMP filtering, asymmetric routing detection |

## Installation

**As a library:**
```toml
[dependencies]
multiprobe = "0.4"
```

**As a CLI tool:**
```bash
cargo install multiprobe
```

## CLI Usage

```bash
# TCP/TLS probes
multiprobe tcp example.com 443
multiprobe tls example.com

# Path discovery (requires elevated privileges)
multiprobe traceroute example.com
multiprobe paris example.com --detect-lb

# Latency analysis
multiprobe latency example.com 443 --samples 50

# Multi-protocol analysis
multiprobe multi example.com --tcp 80,443 --udp 53

# Bidirectional path analysis
multiprobe server                          # On remote host
multiprobe bidirectional server.example.com  # On client

# Protocol Divergence Localization - find where protocols fail differently
multiprobe divergence example.com
multiprobe divergence example.com --protocols icmp,tcp
```

See `multiprobe --help` for all commands and options.

## Quick Start (Library)

```rust
use multiprobe::Probe;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), multiprobe::Error> {
    // TCP probe with timing
    let tcp = Probe::tcp("example.com", 443)
        .timeout(Duration::from_secs(5))
        .send().await?;
    
    println!("Success: {}", tcp.success);
    println!("Latency: {:.2}ms", tcp.timing.total_ms());
    
    Ok(())
}
```

## Multi-Protocol Analysis

```rust
use multiprobe::{Probe, Classifier};

let result = Probe::multi("example.com")
    .tcp(80)
    .tcp(443)
    .udp(53)
    .timeout(Duration::from_secs(5))
    .send().await?;

// Per-protocol results
for probe in &result.results {
    println!("{}: {} ({:.2}ms)", 
        probe.protocol,
        if probe.success { "OK" } else { "FAIL" },
        probe.timing.total_ms());
}

// Path classification
println!("Classification: {}", result.classify());

// Protocol Differential Score
let pds = Classifier::differential_score(&result.results);
println!("Consistency: {:.2}", pds.consistency);
println!("Behavior: {}", pds.interpret());

// Fingerprint
println!("Fingerprint: {}", Classifier::fingerprint(&result.results));
println!("Hash: {:016x}", Classifier::fingerprint_hash(&result.results));
```

## Paris Traceroute

Standard traceroute fails behind ECMP load balancers because it varies flow identifiers between probes. Paris Traceroute (Augustin et al., 2006) maintains constant flow IDs for consistent path discovery.

```rust
use multiprobe::{Probe, ParisMode, FlowId};

// Basic Paris Traceroute
let trace = Probe::paris("example.com")
    .max_hops(30)
    .timeout_per_hop(Duration::from_secs(2))
    .send().await?;

println!("Target: {} ({})", trace.target, trace.target_ip);
println!("Hops: {}", trace.hops.len());
println!("Reached: {}", trace.reached_destination);
println!("Load Balancing: {}", trace.load_balancing);

for hop in &trace.hops {
    let addr = hop.addr.map(|ip| ip.to_string())
        .unwrap_or_else(|| "*".to_string());
    println!("{:2}. {:15} {:.2}ms", 
        hop.ttl, addr, hop.rtt.as_secs_f64() * 1000.0);
}

// With custom flow ID
let trace = Probe::paris("example.com")
    .flow_id(FlowId::udp(33434, 33434))
    .mode(ParisMode::Udp)
    .detect_load_balancing(true)
    .send().await?;

// Discover multiple paths through load balancers
let paths = multiprobe::discover_paths("example.com", 6, &Default::default()).await?;
println!("Found {} distinct paths", paths.len());
```

## TLS Handshake Analysis

```rust
use multiprobe::Probe;

let tls = Probe::tls("example.com")
    .port(443)
    .timeout(Duration::from_secs(10))
    .send().await?;

if tls.success {
    println!("TLS Version: {}", tls.tls_version);
    println!("Cipher: {:?}", tls.cipher_suite);
    println!("HTTP/2: {}", tls.supports_http2());
    println!("Modern TLS: {}", tls.is_modern_tls());
    
    println!("\nTiming Breakdown:");
    println!("  DNS:   {:.2}ms", tls.timing.dns_ms());
    println!("  TCP:   {:.2}ms", tls.timing.tcp_ms());
    println!("  TLS:   {:.2}ms", tls.timing.tls_ms());
    println!("  Total: {:.2}ms", tls.timing.total_ms());
} else {
    println!("TLS failed: {:?}", tls.error);
}
```

## Latency Statistics

```rust
use multiprobe::Probe;

let stats = Probe::latency("example.com", 443)
    .samples(100)
    .interval(Duration::from_millis(100))
    .send().await?;

println!("Samples: {}/{}", stats.success_count, stats.sample_count);
println!("Loss: {:.1}%", stats.loss_rate * 100.0);
println!();
println!("Min:    {:.2}ms", stats.min_rtt.as_secs_f64() * 1000.0);
println!("Max:    {:.2}ms", stats.max_rtt.as_secs_f64() * 1000.0);
println!("Mean:   {:.2}ms", stats.mean_rtt.as_secs_f64() * 1000.0);
println!("Median: {:.2}ms", stats.median_rtt.as_secs_f64() * 1000.0);
println!("P95:    {:.2}ms", stats.p95_rtt.as_secs_f64() * 1000.0);
println!("P99:    {:.2}ms", stats.p99_rtt.as_secs_f64() * 1000.0);
println!("Jitter: {:.2}ms", stats.jitter.as_secs_f64() * 1000.0);
println!("StdDev: {:.2}ms", stats.std_dev.as_secs_f64() * 1000.0);

if stats.has_high_jitter() {
    println!("WARNING: High jitter detected!");
}
if stats.has_packet_loss() {
    println!("WARNING: Packet loss detected!");
}
```

## Path MTU Discovery

```rust
use multiprobe::Probe;

let mtu = Probe::mtu("example.com")
    .min_mtu(68)
    .max_mtu(1500)
    .timeout(Duration::from_secs(2))
    .send().await?;

println!("Path MTU: {} bytes", mtu.path_mtu);
println!("DF Honored: {}", mtu.df_honored);
println!("Frag Needed msgs: {}", mtu.frag_needed_count);
```

## Bufferbloat Detection

```rust
use multiprobe::Probe;

let bloat = Probe::bufferbloat("example.com")
    .port(443)
    .baseline_samples(10)
    .loaded_samples(10)
    .send().await?;

println!("Baseline: {:.2}ms", bloat.baseline_latency.as_secs_f64() * 1000.0);
println!("Under Load: {:.2}ms", bloat.loaded_latency.as_secs_f64() * 1000.0);
println!("Bloat Factor: {:.2}x", bloat.bloat_factor);
println!("Grade: {}", bloat.grade);  // A-F rating
println!("Detected: {}", bloat.detected);
```

## Bidirectional Path Probing

Detect reverse-path asymmetry where packets take different ECMP paths in each direction.

**Server side** (run on the remote host):
```rust
use multiprobe::BidirectionalServer;

let server = BidirectionalServer::bind("0.0.0.0:33435").await?;
server.run().await?;
```

**Client side:**
```rust
use multiprobe::Probe;

let result = Probe::bidirectional("server.example.com")
    .port(33435)
    .probe_count(20)
    .send().await?;

println!("Forward path:  {:.2}ms avg", result.forward.mean_ms);
println!("Reverse path:  {:.2}ms avg", result.reverse.mean_ms);
println!("Round-trip:    {:.2}ms avg", result.round_trip.mean_ms);
println!("Asymmetry:     {:.2} ({})", result.asymmetry_score, result.interpretation());

if result.asymmetric {
    println!("WARNING: Significant path asymmetry detected!");
}
```

## Protocol Divergence Localization

Find WHERE in the network path different protocols start behaving differently. This is useful for diagnosing firewall rules, middlebox interference, or protocol-specific filtering.

```rust
use multiprobe::{analyze_divergence, DivergenceOptions, DivergenceProtocol};

let options = DivergenceOptions {
    max_hops: 30,
    timeout_per_hop: Duration::from_secs(2),
    protocols: vec![
        DivergenceProtocol::Icmp,
        DivergenceProtocol::Tcp,
        DivergenceProtocol::Udp,
    ],
    tcp_port: 80,
    udp_port: 33434,
};

let result = analyze_divergence("example.com", &options).await?;

// Check for divergence
if let Some(hop) = result.first_divergence_hop {
    println!("Protocol divergence at hop {}", hop);
    if let Some(div_hop) = result.divergence_point() {
        println!("  Description: {:?}", div_hop.divergence_description);
    }
} else {
    println!("No divergence - all protocols behave consistently");
}

// Per-hop analysis
for hop in &result.hops {
    print!("Hop {:2}: ", hop.ttl);
    for (proto, status) in &hop.results {
        print!("{}: {} | ", proto, status);
    }
    if hop.has_divergence {
        println!("⚠ DIVERGENCE");
    } else {
        println!();
    }
}

// Summary metrics
println!("Path divergence score: {:.2}", result.path_divergence_score);
println!("Protocols that reached destination: {:?}", result.protocols_reached);
```

Example output:
```
Protocol Divergence Analysis: blocked-host.example.com
Hop  1:  ICMP: 192.168.1.1 (1.23ms) | TCP: 192.168.1.1 (1.45ms) | UDP: 192.168.1.1 (1.12ms)
Hop  2:  ICMP: 10.0.0.1 (5.67ms)    | TCP: 10.0.0.1 (5.89ms)    | UDP: 10.0.0.1 (5.34ms)
Hop  3:  ICMP: 172.16.0.1 (8.90ms)  | TCP: * (timeout)          | UDP: * (timeout)  ⚠ DIVERGENCE

Protocol divergence at hop 3
  Description: ICMP succeeded, TCP/UDP failed
  Likely cause: Firewall or ACL blocking TCP/UDP at 172.16.0.1
```

## Path Classification

| Classification | Description |
|---------------|-------------|
| `Open` | All protocols succeed |
| `IcmpFiltered` | ICMP blocked, TCP/UDP pass |
| `TcpFiltered` | ICMP passes, TCP blocked |
| `SelectiveFirewall` | Some ports open, some closed |
| `Blocked` | All protocols fail |
| `NatDetected` | TTL variance indicates NAT |

## Protocol Differential Score

Quantifies behavioral differences across protocols:

```rust
use multiprobe::Classifier;

let pds = Classifier::differential_score(&results);

// Differentials (0.0 = identical, 1.0 = completely different)
println!("ICMP vs TCP: {:.2}", pds.icmp_tcp_diff);
println!("ICMP vs UDP: {:.2}", pds.icmp_udp_diff);
println!("TCP vs UDP:  {:.2}", pds.tcp_udp_diff);

// Consistency (1.0 = all protocols identical)
println!("Consistency: {:.2}", pds.consistency);

// Latency variance
println!("Latency Variance: {:.2}ms", pds.latency_variance_ms);

// Interpreted behavior
use multiprobe::NetworkBehavior;
match pds.interpret() {
    NetworkBehavior::Direct => println!("Direct path"),
    NetworkBehavior::IcmpFiltering => println!("ICMP filtering"),
    NetworkBehavior::ProtocolSpecificFiltering => println!("Protocol filtering"),
    NetworkBehavior::AsymmetricRouting => println!("Asymmetric routing"),
    NetworkBehavior::Unknown => println!("Unknown"),
}
```

## Load Balancing Detection

```rust
use multiprobe::LoadBalancingType;

let trace = Probe::paris("example.com")
    .detect_load_balancing(true)
    .send().await?;

match trace.load_balancing {
    LoadBalancingType::None => println!("No load balancing"),
    LoadBalancingType::PerFlow => println!("Per-flow ECMP"),
    LoadBalancingType::PerPacket => println!("Per-packet ECMP"),
    LoadBalancingType::Unknown => println!("Unknown"),
}
```

## Permissions

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| TCP/UDP probes | None | None | None |
| TLS probes | None | None | None |
| Latency stats | None | None | None |
| ICMP ping | CAP_NET_RAW | root | Admin |
| Traceroute | CAP_NET_RAW | root | Admin |
| Paris Traceroute | CAP_NET_RAW | root | Admin |
| Protocol Divergence | CAP_NET_RAW | root | Admin |
| MTU Discovery | CAP_NET_RAW | root | Admin |

```bash
# Linux: Grant capability
sudo setcap cap_net_raw+ep ./your-binary

# macOS/Linux: Run with sudo
sudo ./your-binary
```

## API Reference

### Probe Builders

```rust
Probe::tcp(target, port)      // TCP connect probe
Probe::udp(target, port)      // UDP probe
Probe::icmp(target)           // ICMP ping
Probe::multi(target)          // Multi-protocol
Probe::traceroute(target)     // Standard traceroute
Probe::paris(target)          // Paris Traceroute
Probe::tls(target)            // TLS handshake
Probe::latency(target, port)  // Latency statistics
Probe::mtu(target)            // Path MTU discovery
Probe::bufferbloat(target)    // Bufferbloat detection
```

### Standalone Functions

```rust
multiprobe::paris_traceroute(target, &options)  // Paris trace
multiprobe::discover_paths(target, flows, &options)  // Multi-path
multiprobe::analyze_divergence(target, &options)  // Protocol divergence
multiprobe::measure_latency(target, port, samples, interval)
multiprobe::discover_path_mtu(target, &options)
multiprobe::detect_bufferbloat(target, &options)
multiprobe::analyze_reordering(target, port, packets)
multiprobe::probe_tls(target, &options)
multiprobe::compare_tls(target1, target2, &options)
```

## References

- **Paris Traceroute**: Augustin et al., "Avoiding traceroute anomalies with Paris traceroute" (IMC 2006)
- **RFC 3550**: RTP jitter calculation
- **RFC 1191**: Path MTU Discovery
- **Bufferbloat**: Gettys & Nichols, "Bufferbloat: Dark Buffers in the Internet" (2012)

## License

MIT OR Apache-2.0
