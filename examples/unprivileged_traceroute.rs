//! Unprivileged UDP traceroute (Linux only — no sudo required)
//!
//! Uses `IP_RECVERR` + `MSG_ERRQUEUE` so ICMP TTL-exceeded messages are
//! delivered to the sending socket's error queue without a raw socket.
//! This is the same mechanism used by `mtr --udp` in unprivileged mode.
//!
//! On non-Linux platforms this returns an error — use Paris Traceroute
//! with the default Udp mode and sudo instead.
//!
//! Run: cargo run --example unprivileged_traceroute [target]
//!      (no sudo needed on Linux)

use multiprobe::{paris_traceroute, ParisOptions, ParisMode};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = std::env::args().nth(1).unwrap_or_else(|| "8.8.8.8".to_string());

    println!("=== Unprivileged UDP Traceroute (no sudo) ===\n");
    println!("Target: {}", target);

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("This example requires Linux (IP_RECVERR / MSG_ERRQUEUE).");
        eprintln!("On macOS/Windows, use the paris_traceroute example with sudo instead.");
        std::process::exit(1);
    }

    #[cfg(target_os = "linux")]
    {
        let opts = ParisOptions {
            mode: ParisMode::UdpUnprivileged,
            max_hops: 30,
            timeout_per_hop: Duration::from_secs(2),
            probes_per_hop: 3,
            ..Default::default()
        };

        match paris_traceroute(&target, &opts).await {
            Ok(result) => {
                println!("  Hop  IP                   RTT");
                println!("  ───  ───────────────────  ────────");

                for hop in &result.hops {
                    let ip = hop.addr.map(|a| a.to_string()).unwrap_or("*".into());
                    let rtt = if hop.responded {
                        format!("{:.2}ms", hop.rtt.as_secs_f64() * 1000.0)
                    } else {
                        "*".into()
                    };
                    println!("  {:>3}  {:<19}  {}", hop.ttl, ip, rtt);

                    if let Some(addr) = hop.addr {
                        if addr.to_string() == target || result.reached_destination {
                            break;
                        }
                    }
                }

                println!("\nReached destination: {}", result.reached_destination);
                println!("Load balancing: {}", result.load_balancing);
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                if e.to_string().contains("Permission") || e.to_string().contains("permission") {
                    eprintln!("Unexpected permission error — are you on Linux?");
                }
            }
        }
    }

    Ok(())
}
