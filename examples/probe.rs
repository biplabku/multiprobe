//! Example: Multi-protocol network probing
//!
//! Run with: cargo run --example probe -- <target>
//!
//! Examples:
//!   cargo run --example probe -- google.com
//!   cargo run --example probe -- 8.8.8.8

use multiprobe::Probe;
use std::env;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = env::args().nth(1).unwrap_or_else(|| "google.com".to_string());

    println!("Probing: {target}");
    println!("{}", "=".repeat(50));

    // TCP probe to common ports
    println!("\n[TCP Probes]");
    for port in [80, 443, 22, 8080] {
        let result = Probe::tcp(&target, port)
            .timeout(Duration::from_secs(3))
            .send()
            .await;

        match result {
            Ok(r) => {
                let status = if r.success { "OPEN" } else { "CLOSED/FILTERED" };
                println!("  TCP/{}: {} ({:.2}ms)", port, status, r.timing.total_ms());
            }
            Err(e) => {
                println!("  TCP/{port}: ERROR - {e}");
            }
        }
    }

    // UDP probe to DNS
    println!("\n[UDP Probes]");
    let udp_result = Probe::udp(&target, 53)
        .timeout(Duration::from_secs(2))
        .send()
        .await;

    match udp_result {
        Ok(r) => {
            let status = if r.success { "OPEN/FILTERED" } else { "CLOSED" };
            println!("  UDP/53: {} ({:.2}ms)", status, r.timing.total_ms());
        }
        Err(e) => {
            println!("  UDP/53: ERROR - {e}");
        }
    }

    // Multi-protocol probe with classification
    println!("\n[Multi-Protocol Analysis]");
    let multi = Probe::multi(&target)
        .tcp(80)
        .tcp(443)
        .udp(53)
        .timeout(Duration::from_secs(3))
        .send()
        .await?;

    println!("  Results:");
    for probe in &multi.results {
        let status = if probe.success { "OK" } else { "FAIL" };
        println!("    {}: {} ({:.2}ms)", probe.protocol, status, probe.timing.total_ms());
    }

    println!("\n  Path Classification: {}", multi.classify());

    // Protocol Differential Score (your patent IDF-110878!)
    let pds = multiprobe::Classifier::differential_score(&multi.results);
    println!("\n[Protocol Differential Score]");
    println!("  ICMP vs TCP diff:    {:.2}", pds.icmp_tcp_diff);
    println!("  TCP vs UDP diff:     {:.2}", pds.tcp_udp_diff);
    println!("  Path Consistency:    {:.2}", pds.consistency);
    println!("  Latency Variance:    {:.2}ms", pds.latency_variance_ms);
    println!("  Network Behavior:    {}", pds.interpret());

    // Fingerprint for comparison
    println!("\n[Fingerprint]");
    println!("  {}", multiprobe::Classifier::fingerprint(&multi.results));
    println!("  Hash: {:016x}", multiprobe::Classifier::fingerprint_hash(&multi.results));

    // Timing breakdown for a successful probe
    if let Some(tcp443) = multi.results.iter().find(|r| r.protocol == multiprobe::Protocol::Tcp(443) && r.success) {
        println!("\n[Timing Breakdown - TCP/443]");
        if let Some(dns) = tcp443.timing.dns_ms() {
            println!("  DNS Resolution: {dns:.2}ms");
        }
        println!("  TCP Connect:    {:.2}ms", tcp443.timing.connect_ms());
        println!("  Total:          {:.2}ms", tcp443.timing.total_ms());
    }

    // Traceroute
    println!("\n[Traceroute]");
    match Probe::traceroute(&target)
        .max_hops(15)
        .timeout_per_hop(Duration::from_secs(2))
        .send()
        .await
    {
        Ok(trace) => {
            println!("  Target: {} ({})", trace.target, trace.target_ip);
            println!("  Hops: {}, Reached: {}", trace.hop_count(), trace.reached_destination);
            println!("  Path:");
            for hop in &trace.hops {
                let addr_str = match &hop.addr {
                    Some(ip) => ip.to_string(),
                    None => "*".to_string(),
                };
                let icmp_info = match hop.icmp_type {
                    Some(0) => " (Echo Reply - destination)",
                    Some(11) => " (TTL Exceeded)",
                    Some(3) => " (Dest Unreachable)",
                    _ => "",
                };
                println!("    {:2}. {:15} {:.2}ms{}",
                    hop.ttl, addr_str, hop.rtt.as_secs_f64() * 1000.0, icmp_info);
            }
        }
        Err(e) => {
            println!("  Traceroute failed (may need root/admin): {e}");
        }
    }

    Ok(())
}
