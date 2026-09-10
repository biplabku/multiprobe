//! Basic Protocol Probes
//!
//! Demonstrates TCP, UDP, and multi-protocol probing.
//!
//! Run with: cargo run --example basic_probes

use multiprobe::Probe;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = std::env::args().nth(1).unwrap_or_else(|| "google.com".to_string());

    println!("=== Basic Protocol Probes ===\n");
    println!("Target: {}\n", target);

    // TCP Probe
    println!("[TCP Probe - Port 443]");
    let tcp = Probe::tcp(&target, 443)
        .timeout(Duration::from_secs(5))
        .send()
        .await?;

    println!("  Success: {}", tcp.success);
    println!("  Timing:");
    if let Some(dns) = tcp.timing.dns_ms() {
        println!("    DNS:     {:.2}ms", dns);
    }
    println!("    Connect: {:.2}ms", tcp.timing.connect_ms());
    println!("    Total:   {:.2}ms", tcp.timing.total_ms());

    // UDP Probe
    println!("\n[UDP Probe - Port 53]");
    let udp = Probe::udp(&target, 53)
        .timeout(Duration::from_secs(2))
        .send()
        .await?;

    println!("  Success: {}", udp.success);
    println!("  Total:   {:.2}ms", udp.timing.total_ms());

    // Multi-Protocol Probe
    println!("\n[Multi-Protocol Probe]");
    let multi = Probe::multi(&target)
        .tcp(80)
        .tcp(443)
        .udp(53)
        .timeout(Duration::from_secs(5))
        .send()
        .await?;

    println!("  Results:");
    for probe in &multi.results {
        let status = if probe.success { "OK" } else { "FAIL" };
        println!("    {}: {} ({:.2}ms)", probe.protocol, status, probe.timing.total_ms());
    }

    println!("\n  Classification: {}", multi.classify());

    Ok(())
}
