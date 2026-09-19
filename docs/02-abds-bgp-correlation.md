# ABDS: AS-Boundary Divergence Score

## What it measures

When ICMP, TCP, and UDP probes to the same destination take different paths,
something is routing them differently. The key question is **where and why**.

The AS-Boundary Divergence Score (ABDS) answers this by correlating the divergence
hop with BGP topology:

- **ABDS close to 1.0** — divergence is exactly at AS boundaries. A border router
  enforces per-protocol routing policy (e.g. BGP community tags, QoS tiers).
  This is routing-policy driven.

- **ABDS close to 0.0** — divergence is deep inside a single AS. An internal
  firewall, ECMP hash, or QoS classifier treats protocols differently.
  This is internal-policy driven.

This metric is described and evaluated in the ABDS paper:
> "AS-Boundary Divergence Score: Quantifying Routing Asymmetry at Autonomous
>  System Boundaries" — arXiv:2609.14835, IEEE TNSM (under review)

## Basic usage

```rust
use multiprobe::{correlate_divergence, CorrelationOptions, DivergenceCause};

let result = correlate_divergence("8.8.8.8", &CorrelationOptions::default()).await?;

// The ABDS score
println!("ABDS: {:.4}", result.abds.score);
println!("Interpretation: {}", result.abds.interpretation);

// Root cause classification
match &result.primary_cause {
    DivergenceCause::AsBoundaryPolicy { from_asn, to_asn } => {
        println!("Routing policy at AS{} → AS{} boundary", from_asn, to_asn);
    }
    DivergenceCause::IntraAsPolicy { asn } => {
        println!("Internal policy within AS{}", asn);
    }
    DivergenceCause::CloudProviderEdge { provider_name, .. } => {
        println!("Cloud provider edge: {}", provider_name);
    }
    DivergenceCause::TransitProvider { transit_asn } => {
        println!("Transit provider: AS{}", transit_asn);
    }
    DivergenceCause::Unknown => {
        println!("Could not determine (private IPs or lookup failure)");
    }
}
```

## What the result contains

```rust
BgpCorrelatedResult {
    target: String,             // target hostname
    target_ip: IpAddr,          // resolved IP
    hops: Vec<BgpCorrelatedHop>, // per-hop analysis
    first_divergence_hop: Option<u8>, // hop where divergence starts
    as_path: Vec<u32>,          // ordered list of ASNs on path
    as_transitions: usize,      // number of AS boundary crossings
    abds: AsBoundaryDivergenceScore, // the score
    primary_cause: DivergenceCause,  // classification
    total_time: Duration,
}
```

Each `BgpCorrelatedHop`:
```rust
BgpCorrelatedHop {
    ttl: u8,
    addr: Option<IpAddr>,
    asn_info: Option<AsnInfo>,     // ASN, name, country
    protocol_results: HashMap<DivergenceProtocol, HopStatus>,
    has_divergence: bool,
    is_as_boundary: bool,
    prev_asn: Option<u32>,
    divergence_cause: Option<DivergenceCause>,
}
```

## Direct ASN lookup

For quick IP → ASN mapping without running a full traceroute:

```rust
use multiprobe::AsnLookup;
use std::net::{IpAddr, Ipv4Addr};

let lookup = AsnLookup::new().await?;
let info = lookup.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).await?;

println!("ASN: AS{}", info.asn);
println!("Prefix: {}", info.prefix);
println!("Name: {}", info.as_name.unwrap_or_default());
println!("Is cloud provider: {}", info.is_cloud_provider());
println!("Is transit: {}", info.is_transit());
```

Batch lookup:
```rust
let results = lookup.lookup_batch(&ips).await;
```

Uses Team Cymru's DNS-based IP-to-ASN service. Results are cached in memory.

## Configuration

```rust
let opts = CorrelationOptions {
    divergence: DivergenceOptions {
        max_hops: 20,
        timeout_per_hop: Duration::from_secs(2),
        probes_per_hop: 3,
        ..Default::default()
    },
    lookup_as_names: true,  // resolve AS names (slower but more informative)
    cache_asn: true,        // cache ASN lookups in memory
};
```

## Running the example

```bash
sudo cargo run --example bgp_correlation 8.8.8.8
sudo cargo run --example bgp_correlation 1.1.1.1
sudo cargo run --example bgp_correlation your-target.example.com
```
