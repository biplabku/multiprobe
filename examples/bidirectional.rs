//! Bidirectional Path Asymmetry Measurement
//!
//! Measures forward and reverse path latency independently, detecting
//! routing asymmetry where the path from A→B differs from B→A.
//!
//! This is common in networks with:
//!   - ECMP (Equal-Cost Multi-Path) routing with different hash results
//!   - BGP hot-potato vs cold-potato routing
//!   - Traffic engineering policies
//!
//! The asymmetry score is 0.0 (perfectly symmetric) to 1.0 (highly asymmetric).
//!
//! HOW IT WORKS:
//!   1. Client sends a probe to the server
//!   2. Server immediately echoes it back with a timestamp
//!   3. Client computes forward latency (from server's timestamp)
//!      and reverse latency (from echo receipt time)
//!   4. Asymmetry score = |forward - reverse| / (forward + reverse)
//!
//! USAGE:
//!   # Start server on one machine:
//!   cargo run --example bidirectional -- server 0.0.0.0:33435
//!
//!   # Probe from another machine:
//!   cargo run --example bidirectional -- probe <server-ip>

use multiprobe::{BidirectionalServer, BidirectionalOptions, probe_bidirectional, BIDIRECTIONAL_PORT};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("probe");

    match mode {
        "server" => run_server(args.get(2).map(String::as_str)).await?,
        _ => run_probe(args.get(1).map(String::as_str)).await?,
    }

    Ok(())
}

async fn run_server(addr: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let default_addr = format!("0.0.0.0:{}", BIDIRECTIONAL_PORT);
    let bind_addr = addr.unwrap_or(&default_addr);

    println!("=== Bidirectional Probe Server ===\n");
    println!("Listening on: {}", bind_addr);
    println!("Press Ctrl+C to stop.\n");

    let server = BidirectionalServer::bind(bind_addr).await?;

    tokio::select! {
        result = server.run() => {
            result?;
        }
        _ = tokio::signal::ctrl_c() => {
            server.stop();
            println!("\nServer stopped. Handled {} probes.", server.probes_handled());
        }
    }

    Ok(())
}

async fn run_probe(target: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let target = target.unwrap_or("127.0.0.1");

    println!("=== Bidirectional Path Asymmetry Measurement ===\n");
    println!("Target: {}", target);
    println!("Probing forward and reverse paths independently...\n");

    let opts = BidirectionalOptions {
        port: BIDIRECTIONAL_PORT,
        probe_count: 20,
        interval: Duration::from_millis(50),
        timeout: Duration::from_secs(5),
    };

    match probe_bidirectional(target, &opts).await {
        Ok(result) => {
            println!("  Target IP:  {}", result.target_ip);
            println!("  Port:       {}", result.port);
            println!("  Probes:     {}", result.probe_count);
            println!("  Duration:   {:.2}s\n", result.duration.as_secs_f64());

            println!("  ┌────────────────────────────────────────────┐");
            println!("  │  Direction         Min    Mean   Max  Loss  │");
            println!("  ├────────────────────────────────────────────┤");
            println!("  │  Forward (→)   {:6.2}  {:6.2} {:6.2}  {:.1}%  │",
                result.forward.min_ms,
                result.forward.mean_ms,
                result.forward.max_ms,
                result.forward.loss_percent());
            println!("  │  Reverse (←)   {:6.2}  {:6.2} {:6.2}  {:.1}%  │",
                result.reverse.min_ms,
                result.reverse.mean_ms,
                result.reverse.max_ms,
                result.reverse.loss_percent());
            println!("  │  Round-trip    {:6.2}  {:6.2} {:6.2}  {:.1}%  │",
                result.round_trip.min_ms,
                result.round_trip.mean_ms,
                result.round_trip.max_ms,
                result.round_trip.loss_percent());
            println!("  └────────────────────────────────────────────┘");

            println!("\n  Asymmetry score: {:.4}  (0=symmetric, 1=highly asymmetric)",
                result.asymmetry_score);
            println!("  Verdict: {}", result.interpretation());

            if result.asymmetric {
                println!("\n  ⚠ Significant path asymmetry detected.");
                println!("  The forward and reverse paths are likely different.");
                println!("  Possible causes: ECMP, BGP routing policy, traffic engineering.");
            } else {
                println!("\n  ✓ Path is symmetric. Forward and reverse use the same route.");
            }
        }
        Err(e) => {
            eprintln!("  Error: {}", e);
            eprintln!("\n  Is a server running? Start one with:");
            eprintln!("  cargo run --example bidirectional -- server 0.0.0.0:{}", BIDIRECTIONAL_PORT);
        }
    }

    Ok(())
}
