//! Latency Statistics Analysis
//!
//! Demonstrates comprehensive latency measurement with statistical analysis.
//!
//! Run with: cargo run --example latency_analysis -- google.com

use multiprobe::Probe;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = std::env::args().nth(1).unwrap_or_else(|| "google.com".to_string());

    println!("=== Latency Statistics Analysis ===\n");
    println!("Target: {}:443\n", target);

    println!("[Collecting Samples]");
    println!("  Samples: 50");
    println!("  Interval: 100ms");
    println!("  Please wait...\n");

    let stats = Probe::latency(&target, 443)
        .samples(50)
        .interval(Duration::from_millis(100))
        .send()
        .await?;

    println!("[Sample Summary]");
    println!("  Total:     {}", stats.sample_count);
    println!("  Successful: {}", stats.success_count);
    println!("  Lost:      {} ({:.1}%)",
        stats.sample_count - stats.success_count,
        stats.loss_rate * 100.0);

    println!("\n[Latency Statistics]");
    println!("  ┌─────────────┬────────────┐");
    println!("  │ Metric      │ Value      │");
    println!("  ├─────────────┼────────────┤");
    println!("  │ Minimum     │ {:>8.2}ms │", stats.min_rtt.as_secs_f64() * 1000.0);
    println!("  │ Maximum     │ {:>8.2}ms │", stats.max_rtt.as_secs_f64() * 1000.0);
    println!("  │ Mean        │ {:>8.2}ms │", stats.mean_rtt.as_secs_f64() * 1000.0);
    println!("  │ Median      │ {:>8.2}ms │", stats.median_rtt.as_secs_f64() * 1000.0);
    println!("  │ Std Dev     │ {:>8.2}ms │", stats.std_dev.as_secs_f64() * 1000.0);
    println!("  │ Jitter      │ {:>8.2}ms │", stats.jitter.as_secs_f64() * 1000.0);
    println!("  ├─────────────┼────────────┤");
    println!("  │ P95         │ {:>8.2}ms │", stats.p95_rtt.as_secs_f64() * 1000.0);
    println!("  │ P99         │ {:>8.2}ms │", stats.p99_rtt.as_secs_f64() * 1000.0);
    println!("  └─────────────┴────────────┘");

    // Quality assessment
    println!("\n[Quality Assessment]");

    let mean_ms = stats.mean_rtt.as_secs_f64() * 1000.0;
    let quality = if mean_ms < 50.0 {
        "Excellent"
    } else if mean_ms < 100.0 {
        "Good"
    } else if mean_ms < 200.0 {
        "Fair"
    } else {
        "Poor"
    };
    println!("  Latency:    {} ({:.0}ms mean)", quality, mean_ms);

    if stats.has_high_jitter() {
        println!("  Jitter:     HIGH (>{:.0}% of mean RTT)", 10.0);
    } else {
        println!("  Jitter:     Normal");
    }

    if stats.has_packet_loss() {
        println!("  Packet Loss: DETECTED ({:.1}%)", stats.loss_rate * 100.0);
    } else {
        println!("  Packet Loss: None");
    }

    // Histogram visualization
    println!("\n[Latency Distribution]");
    let range = stats.max_rtt.as_secs_f64() * 1000.0 - stats.min_rtt.as_secs_f64() * 1000.0;
    let min_ms = stats.min_rtt.as_secs_f64() * 1000.0;

    if range > 0.0 {
        println!("  {:>6.1}ms ├", min_ms);
        println!("  {:>6.1}ms ├───────────── median", stats.median_rtt.as_secs_f64() * 1000.0);
        println!("  {:>6.1}ms ├─────────────────────── p95", stats.p95_rtt.as_secs_f64() * 1000.0);
        println!("  {:>6.1}ms ├", stats.max_rtt.as_secs_f64() * 1000.0);
    }

    Ok(())
}
