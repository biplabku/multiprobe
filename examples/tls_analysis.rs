//! TLS Handshake Analysis
//!
//! Demonstrates TLS probing with detailed timing breakdown.
//!
//! Run with: cargo run --example tls_analysis -- google.com

use multiprobe::Probe;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = std::env::args().nth(1).unwrap_or_else(|| "google.com".to_string());

    println!("=== TLS Handshake Analysis ===\n");
    println!("Target: {}\n", target);

    let tls = Probe::tls(&target)
        .port(443)
        .timeout(Duration::from_secs(10))
        .send()
        .await?;

    println!("[Connection Status]");
    println!("  Success: {}", tls.success);
    println!("  Target IP: {}", tls.target_ip);

    if tls.success {
        println!("\n[TLS Details]");
        println!("  Version: {}", tls.tls_version);
        println!("  Cipher:  {:?}", tls.cipher_suite);
        println!("  HTTP/2:  {}", tls.supports_http2());
        println!("  Modern:  {}", tls.is_modern_tls());

        println!("\n[Timing Breakdown]");
        println!("  DNS Resolution:  {:>8.2}ms", tls.timing.dns_ms());
        println!("  TCP Connect:     {:>8.2}ms", tls.timing.tcp_ms());
        println!("  TLS Handshake:   {:>8.2}ms", tls.timing.tls_ms());
        println!("  ─────────────────────────");
        println!("  Total:           {:>8.2}ms", tls.timing.total_ms());

        // Visual breakdown bar
        let total = tls.timing.total_ms();
        if total > 0.0 {
            let dns_pct = (tls.timing.dns_ms() / total * 100.0) as usize;
            let tcp_pct = (tls.timing.tcp_ms() / total * 100.0) as usize;
            let tls_pct = (tls.timing.tls_ms() / total * 100.0) as usize;

            println!("\n[Visual Breakdown]");
            println!("  DNS: {:>3}% {}", dns_pct, "█".repeat(dns_pct / 5));
            println!("  TCP: {:>3}% {}", tcp_pct, "█".repeat(tcp_pct / 5));
            println!("  TLS: {:>3}% {}", tls_pct, "█".repeat(tls_pct / 5));
        }
    } else {
        println!("\n[Error]");
        println!("  {}", tls.error.unwrap_or_else(|| "Unknown error".to_string()));
    }

    // Compare multiple targets
    println!("\n[Multi-Target Comparison]");
    let targets = ["google.com", "cloudflare.com", "github.com"];

    for t in targets {
        match Probe::tls(t)
            .timeout(Duration::from_secs(10))
            .send()
            .await
        {
            Ok(r) if r.success => {
                println!("  {:<15} {} {:>8.2}ms",
                    t, r.tls_version, r.timing.total_ms());
            }
            Ok(r) => {
                println!("  {:<15} FAILED: {:?}", t, r.error);
            }
            Err(e) => {
                println!("  {:<15} ERROR: {}", t, e);
            }
        }
    }

    Ok(())
}
