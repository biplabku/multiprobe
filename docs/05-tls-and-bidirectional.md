# TLS Probing and Bidirectional Measurement

## TLS handshake timing

Breaks down TLS connection into DNS, TCP, and TLS stages:

```rust
use multiprobe::probe_tls;

let result = probe_tls("google.com", &Default::default()).await?;

println!("Success:       {}", result.success);
println!("TLS version:   {:?}", result.tls_version);
println!("Cipher suite:  {}", result.cipher_suite.unwrap_or_default());
println!("Cert CN:       {}", result.cert_cn.unwrap_or_default());
println!("Session reuse: {}", result.session_resumed);
println!();
println!("Timing breakdown:");
println!("  DNS:     {:.2}ms", result.timing.dns_ms());
println!("  TCP:     {:.2}ms", result.timing.tcp_ms());
println!("  TLS:     {:.2}ms", result.timing.tls_ms());
println!("  Total:   {:.2}ms", result.timing.total_ms());
```

Compare two endpoints (returns a comparison struct, not a tuple):
```rust
use multiprobe::compare_tls;

let cmp = compare_tls("cloudflare.com", "google.com", &Default::default()).await?;
println!("Same TLS version: {}", cmp.same_version);
println!("Same cipher:      {}", cmp.same_cipher);
println!("Both modern:      {}", cmp.both_modern);
println!("Timing diff:      {:.2}ms", cmp.timing_diff.as_secs_f64() * 1000.0);
```

## Bidirectional path asymmetry

Measures whether the forward path (A→B) has different latency from the
reverse path (B→A). Asymmetry is common with BGP hot-potato routing and ECMP.

**Architecture:** Client sends a probe to the server. Server immediately echoes
it with a timestamp. Client computes forward latency (from server's timestamp)
and reverse latency (from echo receipt time).

### Server side

```rust
use multiprobe::{BidirectionalServer, BIDIRECTIONAL_PORT};

let server = BidirectionalServer::bind(&format!("0.0.0.0:{}", BIDIRECTIONAL_PORT)).await?;
server.run().await?;
```

### Client side

```rust
use multiprobe::{probe_bidirectional, BidirectionalOptions};
use std::time::Duration;

let opts = BidirectionalOptions {
    probe_count: 20,
    interval: Duration::from_millis(100),
    timeout: Duration::from_secs(5),
    ..Default::default()
};

let result = probe_bidirectional("server-ip", &opts).await?;

println!("Forward  → min {:.1}ms  mean {:.1}ms  loss {:.1}%",
    result.forward.min_ms,
    result.forward.mean_ms,
    result.forward.loss_percent());
println!("Reverse  ← min {:.1}ms  mean {:.1}ms  loss {:.1}%",
    result.reverse.min_ms,
    result.reverse.mean_ms,
    result.reverse.loss_percent());
println!("RTT        min {:.1}ms  mean {:.1}ms",
    result.round_trip.min_ms,
    result.round_trip.mean_ms);
println!("Asymmetry score: {:.4}", result.asymmetry_score);
println!("Verdict: {}", result.interpretation());
```

Asymmetry score: 0.0 = fully symmetric, 1.0 = highly asymmetric.

### Example

Start the server:
```bash
cargo run --example bidirectional -- server 0.0.0.0:33435
```

Probe from another machine:
```bash
cargo run --example bidirectional <server-ip>
```
