# Path Analytics

## Latency measurement

Measures RTT statistics with multiple samples:

```rust
use multiprobe::{measure_latency, LatencyStats};
use std::time::Duration;

let stats = measure_latency("8.8.8.8", 10, Duration::from_secs(1)).await?;

println!("Min:    {:.2}ms", stats.min_ms);
println!("Mean:   {:.2}ms", stats.mean_ms);
println!("Max:    {:.2}ms", stats.max_ms);
println!("Stddev: {:.2}ms", stats.stddev_ms);
println!("P50:    {:.2}ms", stats.p50_ms);
println!("P95:    {:.2}ms", stats.p95_ms);
println!("P99:    {:.2}ms", stats.p99_ms);
println!("Loss:   {:.1}%", stats.loss_percent());
```

## Path MTU Discovery

Discovers the maximum packet size that can traverse the path without
fragmentation (RFC 4821):

```rust
use multiprobe::{discover_path_mtu, PmtudOptions};

let result = discover_path_mtu("8.8.8.8", &Default::default()).await?;

println!("Path MTU: {} bytes", result.mtu);
println!("Standard: {} ({})", result.is_standard_mtu(), result.mtu_description());
```

Common MTU values:
- 1500 — Ethernet (standard internet path)
- 1480 — PPPoE (some ISPs)
- 1460 — TCP MSS after IP/TCP headers
- 576 — Minimum required by IPv4

## Bufferbloat detection

Detects if there is excessive buffering on the path (a sign of poor QoS):

```rust
use multiprobe::{detect_bufferbloat, BufferbloatGrade};

let result = detect_bufferbloat("8.8.8.8", &Default::default()).await?;

println!("Grade: {} ({:?})", result.grade, result.grade);
println!("Baseline RTT: {:.2}ms", result.baseline_ms);
println!("Loaded RTT:   {:.2}ms", result.loaded_ms);
println!("Inflation:    {:.1}%", result.inflation_percent);

match result.grade {
    BufferbloatGrade::A => println!("Excellent — minimal buffering"),
    BufferbloatGrade::B => println!("Good"),
    BufferbloatGrade::C => println!("Moderate bufferbloat present"),
    BufferbloatGrade::D => println!("Significant bufferbloat"),
    BufferbloatGrade::F => println!("Severe bufferbloat — QoS problem"),
}
```

## Reordering analysis

Detects whether packets arrive out of order (indicates asymmetric routing
or parallel paths merging at destination):

```rust
use multiprobe::analyze_reordering;

let result = analyze_reordering("8.8.8.8", 50, &Default::default()).await?;

println!("Reordering: {}", result.reordering_detected);
println!("Reorder rate: {:.2}%", result.reorder_percent);
println!("Out-of-order: {} of {}", result.out_of_order, result.total_packets);
```

## Protocol Differential Score

Compares behavior across protocols to detect filtering or QoS differentiation:

```rust
use multiprobe::{Probe, Classifier};

let multi = Probe::multi("target.com")
    .tcp(80)
    .tcp(443)
    .udp(53)
    .icmp()
    .send()
    .await?;

let score = Classifier::differential_score(&multi.results);
println!("Consistency: {:.4}", score.consistency);
println!("Protocol bias: {:.4}", score.protocol_bias);
println!("Behavior: {}", multi.classify());
```

A `consistency` near 1.0 means all protocols behave the same.
A low value indicates protocol-based filtering or QoS.
