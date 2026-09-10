//! Paris Traceroute Example
//!
//! Demonstrates ECMP-aware traceroute with load balancing detection.
//!
//! Run with: sudo cargo run --example paris_traceroute -- google.com
//!
//! Note: Requires elevated privileges (CAP_NET_RAW on Linux, root on macOS)

use multiprobe::{Probe, ParisMode, FlowId, discover_paths};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = std::env::args().nth(1).unwrap_or_else(|| "google.com".to_string());

    println!("=== Paris Traceroute ===\n");
    println!("Target: {}\n", target);

    // Basic Paris Traceroute
    println!("[Paris Traceroute - UDP Mode]");
    let trace = Probe::paris(&target)
        .max_hops(20)
        .timeout_per_hop(Duration::from_secs(2))
        .mode(ParisMode::Udp)
        .detect_load_balancing(true)
        .send()
        .await?;

    println!("  Target IP: {}", trace.target_ip);
    println!("  Reached:   {}", trace.reached_destination);
    println!("  Load Balancing: {}", trace.load_balancing);
    println!("  Total Time: {:.2}ms", trace.total_time.as_secs_f64() * 1000.0);
    println!("\n  Hops:");

    for hop in &trace.hops {
        let addr = hop.addr
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "*".to_string());

        let icmp_info = match hop.icmp_type {
            Some(0) => " [Echo Reply]",
            Some(3) => " [Unreachable]",
            Some(11) => " [TTL Exceeded]",
            _ => "",
        };

        println!("  {:2}. {:15} {:>8.2}ms{}",
            hop.ttl, addr, hop.rtt.as_secs_f64() * 1000.0, icmp_info);
    }

    // Multi-path discovery
    println!("\n[Multi-Path Discovery]");
    println!("  Testing 4 different flows...\n");

    match discover_paths(&target, 4, &Default::default()).await {
        Ok(paths) => {
            for (i, path) in paths.iter().enumerate() {
                let ips: Vec<String> = path.path().iter()
                    .map(|ip| ip.to_string())
                    .collect();
                println!("  Flow {}: {} hops", i + 1, ips.len());
                if !ips.is_empty() {
                    println!("    Path: {}", ips.join(" -> "));
                }
            }

            // Check for path diversity
            let unique_paths: std::collections::HashSet<Vec<_>> = paths.iter()
                .map(|p| p.path())
                .collect();

            if unique_paths.len() > 1 {
                println!("\n  ECMP Detected: {} unique paths found!", unique_paths.len());
            } else {
                println!("\n  Single path - no ECMP detected");
            }
        }
        Err(e) => {
            println!("  Error: {} (may need elevated privileges)", e);
        }
    }

    // Custom flow ID example
    println!("\n[Custom Flow ID]");
    let custom_flow = FlowId::udp(12345, 33434);
    println!("  Using flow: src_port={}, dst_port={}",
        custom_flow.src_port, custom_flow.dst_port);

    Ok(())
}
