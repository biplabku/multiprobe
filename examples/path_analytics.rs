//! Path Analytics Example
//!
//! Demonstrates MTU discovery, bufferbloat detection, and Protocol Differential Score.
//!
//! Run with: cargo run --example path_analytics -- google.com
//!
//! Note: MTU discovery requires elevated privileges

use multiprobe::{Probe, Classifier};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = std::env::args().nth(1).unwrap_or_else(|| "google.com".to_string());

    println!("=== Path Analytics ===\n");
    println!("Target: {}\n", target);

    // Protocol Differential Score
    println!("[Protocol Differential Score]");
    println!("  Running multi-protocol probe...\n");

    let multi = Probe::multi(&target)
        .tcp(80)
        .tcp(443)
        .udp(53)
        .timeout(Duration::from_secs(5))
        .send()
        .await?;

    let pds = Classifier::differential_score(&multi.results);

    println!("  Protocol Differentials (0.0=same, 1.0=different):");
    println!("    ICMP vs TCP: {:.2}", pds.icmp_tcp_diff);
    println!("    ICMP vs UDP: {:.2}", pds.icmp_udp_diff);
    println!("    TCP vs UDP:  {:.2}", pds.tcp_udp_diff);
    println!();
    println!("  Consistency:      {:.2} (1.0 = all identical)", pds.consistency);
    println!("  Latency Variance: {:.2}ms", pds.latency_variance_ms);
    println!("  Behavior:         {}", pds.interpret());

    // Network Fingerprint
    println!("\n[Network Fingerprint]");
    let fingerprint = Classifier::fingerprint(&multi.results);
    let hash = Classifier::fingerprint_hash(&multi.results);
    println!("  Fingerprint: {}", fingerprint);
    println!("  Hash:        {:016x}", hash);

    // Path MTU Discovery (requires privileges)
    println!("\n[Path MTU Discovery]");
    match Probe::mtu(&target)
        .min_mtu(576)
        .max_mtu(1500)
        .timeout(Duration::from_secs(2))
        .send()
        .await
    {
        Ok(mtu) => {
            println!("  Path MTU:        {} bytes", mtu.path_mtu);
            println!("  DF Honored:      {}", mtu.df_honored);
            println!("  Frag Needed:     {} messages", mtu.frag_needed_count);

            let mtu_quality = if mtu.path_mtu >= 1500 {
                "Standard Ethernet"
            } else if mtu.path_mtu >= 1400 {
                "Slightly reduced (VPN/tunnel?)"
            } else if mtu.path_mtu >= 1280 {
                "IPv6 minimum"
            } else {
                "Significantly reduced"
            };
            println!("  Assessment:      {}", mtu_quality);
        }
        Err(e) => {
            println!("  Error: {} (may need elevated privileges)", e);
        }
    }

    // Bufferbloat Detection
    println!("\n[Bufferbloat Detection]");
    println!("  Measuring baseline vs loaded latency...\n");

    match Probe::bufferbloat(&target)
        .port(443)
        .baseline_samples(5)
        .loaded_samples(5)
        .send()
        .await
    {
        Ok(bloat) => {
            println!("  Baseline Latency: {:.2}ms",
                bloat.baseline_latency.as_secs_f64() * 1000.0);
            println!("  Loaded Latency:   {:.2}ms",
                bloat.loaded_latency.as_secs_f64() * 1000.0);
            println!("  Bloat Factor:     {:.2}x", bloat.bloat_factor);
            println!();
            println!("  Grade:    {}", bloat.grade);
            println!("  Detected: {}", if bloat.detected { "YES" } else { "No" });

            if bloat.detected {
                println!("\n  Recommendation: Consider enabling AQM (fq_codel, cake)");
            }
        }
        Err(e) => {
            println!("  Error: {}", e);
        }
    }

    // Path Classification
    println!("\n[Path Classification]");
    println!("  Classification: {}", multi.classify());

    Ok(())
}
