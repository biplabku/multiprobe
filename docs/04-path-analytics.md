# Path Analytics

## Latency measurement

Measures RTT statistics with multiple samples. Requires a port (TCP connect):

```rust
use multiprobe::{measure_latency};
use std::time::Duration;

let stats = measure_latency("8.8.8.8", 53, 10, Duration::from_millis(100)).await?;
//                           target   port  n   interval

println!("Min:    {:.2}ms", stats.min_rtt.as_secs_f64() * 1000.0);
println!("Mean:   {:.2}ms", stats.mean_rtt.as_secs_f64() * 1000.0);
println!("Max:    {:.2}ms", stats.max_rtt.as_secs_f64() * 1000.0);
println!("Stddev: {:.2}ms", stats.std_dev.as_secs_f64() * 1000.0);
println!("P95:    {:.2}ms", stats.p95_rtt.as_secs_f64() * 1000.0);
println!("P99:    {:.2}ms", stats.p99_rtt.as_secs_f64() * 1000.0);
println!("Loss:   {:.1}%", stats.loss_rate * 100.0);
println!("Sent:   {}", stats.sample_count);
println!("OK:     {}", stats.success_count);
```

## Path MTU Discovery

Discovers the maximum packet size that can traverse the path without
fragmentation:

```rust
use multiprobe::discover_path_mtu;

let result = discover_path_mtu("8.8.8.8", &Default::default()).await?;

println!("Path MTU: {} bytes", result.path_mtu);
println!("DF honored: {}", result.df_honored);
println!("Success: {}", result.success);
```

Common MTU values: 1500 (Ethernet), 1480 (PPPoE), 576 (IPv4 minimum).

## Bufferbloat detection

Detects if there is excessive buffering on the path:

```rust
use multiprobe::{detect_bufferbloat, BufferbloatGrade};
use std::time::Duration;

let result = detect_bufferbloat("8.8.8.8", &Default::default()).await?;

let baseline_ms = result.baseline_latency.as_secs_f64() * 1000.0;
let loaded_ms   = result.loaded_latency.as_secs_f64() * 1000.0;

println!("Grade:    {:?}", result.grade);
println!("Baseline: {:.2}ms", baseline_ms);
println!("Loaded:   {:.2}ms", loaded_ms);
println!("Factor:   {:.2}x", result.bloat_factor);
println!("Detected: {}", result.detected);

match result.grade {
    BufferbloatGrade::A => println!("Excellent — minimal buffering"),
    BufferbloatGrade::B => println!("Good"),
    BufferbloatGrade::C => println!("Moderate bufferbloat present"),
    BufferbloatGrade::D => println!("Significant bufferbloat"),
    BufferbloatGrade::F => println!("Severe bufferbloat — QoS problem"),
}
```

## Reordering analysis

Detects whether packets arrive out of order:

```rust
use multiprobe::analyze_reordering;

let result = analyze_reordering("8.8.8.8", 53, 50).await?;
//                               target   port  packets

println!("Has reordering: {}", result.has_reordering());
println!("Reorder rate:   {:.2}%", result.reorder_rate * 100.0);
println!("Out of order:   {} of {}", result.out_of_order, result.packets_sent);
println!("Max extent:     {} hops", result.max_reorder_extent);
println!("Duplicates:     {}", result.duplicates);
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
println!("Consistency:    {:.4}", score.consistency);
println!("Protocol bias:  {:.4}", score.protocol_bias);
println!("Behavior:       {}", multi.classify());
```

A `consistency` near 1.0 means all protocols behave the same.
A low value indicates protocol-based filtering or QoS.
