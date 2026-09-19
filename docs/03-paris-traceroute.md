# Paris Traceroute

## Why Paris Traceroute

Standard traceroute varies the IP ID or TTL across probes. In ECMP (Equal-Cost
Multi-Path) networks, this causes different probes to take different paths — you
see apparent "loops" or inconsistent hops that are actually different routers
at the same distance.

Paris Traceroute fixes this by keeping the flow identifier constant:
all probes for a given traceroute share the same `(src_port, dst_port)` so ECMP
routers hash them to the same next hop. The path you see is the real path for
that flow.

## Basic usage

```rust
use multiprobe::paris_traceroute;
use std::time::Duration;

let result = paris_traceroute("8.8.8.8", &Default::default()).await?;

for hop in &result.hops {
    let ip = hop.addr.map(|a| a.to_string()).unwrap_or("*".into());
    let rtt = hop.rtt_ms.unwrap_or(0.0);
    let asn = hop.asn.map(|a| format!(" AS{}", a)).unwrap_or_default();
    println!("  {:>2}  {:<18}  {:.2}ms{}", hop.ttl, ip, rtt, asn);
}

println!("Reached destination: {}", result.reached_destination);
println!("Load balancing: {}", result.load_balancing);
```

## Detecting ECMP paths

`discover_paths` sends probes on multiple flows and detects how many distinct
paths exist:

```rust
use multiprobe::discover_paths;

let paths = discover_paths("8.8.8.8", 5, &Default::default()).await?;

println!("Found {} distinct paths", paths.len());
for (i, path) in paths.iter().enumerate() {
    println!("Path {}: {} hops", i + 1, path.hops.len());
}
```

## Configuration

```rust
use multiprobe::{ParisOptions, ParisMode, FlowId};

let opts = ParisOptions {
    max_hops: 30,
    timeout_per_hop: Duration::from_secs(2),
    probes_per_hop: 3,
    mode: ParisMode::Udp,  // Udp (default), Tcp, or Icmp
    flow_id: Some(FlowId::udp(12345, 33435)), // fix the flow
    detect_load_balancing: true,
    ..Default::default()
};
```

## Modes

| Mode | How it works | Notes |
|------|-------------|-------|
| `UDP` (default) | UDP probes, constant src/dst ports | Most compatible |
| `TCP` | TCP SYN probes | Bypasses UDP filters |
| `ICMP` | ICMP echo with constant ID | Requires CAP_NET_RAW |

## What you get per hop

```rust
ParisHop {
    ttl: u8,
    addr: Option<IpAddr>,
    rtt_ms: Option<f64>,
    asn: Option<u32>,
    mpls_labels: Vec<MplsLabel>,  // MPLS label stack if present
    from_different_path: bool,    // true if this hop is on an alternate path
}
```

## Running the example

```bash
sudo cargo run --example paris_traceroute 8.8.8.8
sudo cargo run --example paris_traceroute 8.8.8.8 -- --mode tcp --flows 3
```
