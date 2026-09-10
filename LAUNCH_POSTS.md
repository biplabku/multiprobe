# Launch Announcements

## Reddit r/rust

**Title:** `multiprobe: Paris Traceroute, Path Analytics & TLS Timing in Pure Rust`

**Body:**
```
I just published multiprobe, a multi-protocol network probing library with some features I couldn't find elsewhere in the Rust ecosystem:

**Key Features:**
- **Paris Traceroute** - ECMP-aware traceroute that maintains flow consistency (first pure-Rust implementation I'm aware of)
- **Path Analytics** - Jitter (p95/p99), MTU discovery, bufferbloat detection with A-F grading
- **TLS Handshake Timing** - Detailed breakdown (DNS → TCP → TLS)
- **Protocol Differential Score** - Quantify how differently ICMP/TCP/UDP behave on a path

**Quick Example:**
```rust
// Paris Traceroute with load balancing detection
let trace = Probe::paris("example.com")
    .detect_load_balancing(true)
    .send().await?;

println!("Load balancing: {}", trace.load_balancing);

// Latency statistics
let stats = Probe::latency("example.com", 443)
    .samples(100)
    .send().await?;

println!("P99: {:.2}ms, Jitter: {:.2}ms", 
    stats.p99_rtt.as_secs_f64() * 1000.0,
    stats.jitter.as_secs_f64() * 1000.0);
```

- **GitHub:** https://github.com/biplabku/multiprobe
- **crates.io:** https://crates.io/crates/multiprobe
- **docs.rs:** https://docs.rs/multiprobe

Would love feedback, especially on the API design. Issues and PRs welcome!
```

---

## Hacker News (Show HN)

**Title:** `Show HN: multiprobe – Paris Traceroute and Path Analytics in Pure Rust`

**Body:**
```
I built multiprobe because I needed ECMP-aware traceroute and path quality metrics for network monitoring, and couldn't find a Rust library that did both.

Main features:
- Paris Traceroute (handles load balancers correctly, unlike standard traceroute)
- Latency statistics with p95/p99/jitter
- Path MTU discovery
- Bufferbloat detection (grades A-F)
- TLS handshake timing breakdown
- Protocol Differential Score (compares ICMP vs TCP vs UDP behavior)

It's async (tokio) and has 100+ tests.

GitHub: https://github.com/biplabku/multiprobe
crates.io: https://crates.io/crates/multiprobe

Happy to answer questions about the implementation, especially the Paris Traceroute algorithm.
```

---

## Rust Users Forum

**Title:** `[ANN] multiprobe 0.1.0 - Multi-protocol network probing with Paris Traceroute`

**Body:**
```
Hi everyone,

I'm happy to announce the first release of `multiprobe`, a network probing library focused on path analysis.

## Why I Built This

Standard traceroute breaks behind ECMP load balancers. Paris Traceroute (Augustin et al., 2006) solves this by maintaining constant flow identifiers. I couldn't find a pure-Rust implementation, so I built one along with other path analytics I needed.

## Features

- **Protocol Probes**: TCP, UDP, ICMP, TLS with timing breakdown
- **Paris Traceroute**: ECMP-aware path discovery with load balancing detection
- **Path Analytics**: 
  - Latency stats (min/max/mean/median/p95/p99/jitter/stddev)
  - Path MTU discovery
  - Bufferbloat detection
  - Packet reordering analysis
- **Classification**: Path fingerprinting, Protocol Differential Score

## Links

- [crates.io](https://crates.io/crates/multiprobe)
- [docs.rs](https://docs.rs/multiprobe)
- [GitHub](https://github.com/biplabku/multiprobe)

Feedback welcome! I'm particularly interested in:
- API ergonomics suggestions
- Additional protocols to support (QUIC?)
- Performance optimization ideas

Thanks!
```

---

## LinkedIn Post (Professional)

```
Excited to announce the release of multiprobe - an open-source Rust library for network path analysis.

Key capabilities:
• Paris Traceroute for accurate path discovery behind load balancers
• Latency analytics with p95/p99 percentiles and jitter measurement  
• Path MTU discovery and bufferbloat detection
• TLS handshake timing breakdown

Built this to solve real problems I encountered in network monitoring. Now available on crates.io for the Rust community.

GitHub: https://github.com/biplabku/multiprobe

#rust #networking #opensource #observability
```

---

## Twitter/X

```
Just published multiprobe 🦀

A Rust library for network path analysis:
✅ Paris Traceroute (ECMP-aware)
✅ Latency stats (p95/p99/jitter)
✅ MTU discovery
✅ Bufferbloat detection
✅ TLS timing breakdown

crates.io/crates/multiprobe
github.com/biplabku/multiprobe

#rustlang
```
