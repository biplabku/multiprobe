//! BGP Correlation and AS-Boundary Divergence Score (ABDS)
//!
//! Demonstrates the core novel contribution of multiprobe: correlating
//! protocol-level path divergence with BGP topology to automatically
//! classify the ROOT CAUSE of divergence.
//!
//! The AS-Boundary Divergence Score (ABDS) answers:
//!   "Is the divergence caused by routing policy (BGP) or by
//!    internal network policy at a specific AS?"
//!
//! ABDS close to 1.0 → divergence is at AS boundaries (routing-policy driven)
//! ABDS close to 0.0 → divergence is inside a single AS (internal-policy driven)
//!
//! This implements the metric from:
//!   "AS-Boundary Divergence Score: Quantifying Routing Asymmetry
//!    at Autonomous System Boundaries"
//!   arXiv:2609.14835 — IEEE TNSM under review
//!
//! Run: sudo cargo run --example bgp_correlation [target]
//! (CAP_NET_RAW required for ICMP traceroute)

use multiprobe::{correlate_divergence, AsnLookup, CorrelationOptions, DivergenceCause};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = std::env::args().nth(1).unwrap_or_else(|| "8.8.8.8".to_string());

    println!("=== BGP Correlation + ABDS Analysis ===\n");
    println!("Target: {}", target);
    println!("Note: requires CAP_NET_RAW / sudo for ICMP probing\n");

    // ── Step 1: Direct ASN lookup ──────────────────────────────────────────────
    println!("[Step 1] ASN Lookup");
    let asn_lookup = AsnLookup::new().await?;

    if let Ok(ip) = target.parse::<std::net::IpAddr>() {
        match asn_lookup.lookup(ip).await {
            Ok(info) => {
                println!("  IP:       {}", ip);
                println!("  ASN:      AS{}", info.asn);
                println!("  Prefix:   {}", info.prefix);
                println!("  Name:     {}", info.as_name.as_deref().unwrap_or("unknown"));
                println!("  Country:  {}", info.country.as_deref().unwrap_or("unknown"));
                println!("  Cloud:    {}", info.is_cloud_provider());
                println!("  Transit:  {}", info.is_transit());
            }
            Err(e) => println!("  ASN lookup failed: {} (private IP or network issue)", e),
        }
    } else {
        println!("  Hostname — ASN resolved per-hop during traceroute");
    }

    // ── Step 2: BGP-correlated divergence analysis ─────────────────────────────
    println!("\n[Step 2] BGP-Correlated Divergence Analysis");
    println!("  Running ICMP + TCP + UDP traceroutes simultaneously...\n");

    let opts = CorrelationOptions::default();

    match correlate_divergence(&target, &opts).await {
        Ok(result) => {
            // ── Per-hop table ─────────────────────────────────────────────────
            println!("  Hop  IP                  ASN        Boundary  Divergence");
            println!("  ───  ──────────────────  ─────────  ────────  ──────────");

            for hop in &result.hops {
                let ip_str = hop.addr
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "*".to_string());
                let asn_str = hop.asn()
                    .map(|a| format!("AS{}", a))
                    .unwrap_or_else(|| "?".to_string());
                let boundary = if hop.is_as_boundary { "  ←" } else { "" };
                let diverges = if hop.has_divergence { "  !" } else { "" };

                println!("  {:>3}  {:<18}  {:<9}  {}{}",
                    hop.ttl, ip_str, asn_str, boundary, diverges);
            }

            // ── ABDS Score ────────────────────────────────────────────────────
            println!("\n  ┌──────────────────────────────────────────────┐");
            println!("  │  ABDS Score:  {:.4}", result.abds.score);
            println!("  │  Divergent:   {} hops ({} at boundary, {} intra-AS, {} unknown)",
                result.abds.total_divergent,
                result.abds.at_boundary,
                result.abds.intra_as,
                result.abds.unknown);
            println!("  │  Verdict:     {}", result.abds.interpretation);
            println!("  └──────────────────────────────────────────────┘");

            // ── Primary cause classification ──────────────────────────────────
            println!("\n  Primary Cause: {}", result.primary_cause);
            match &result.primary_cause {
                DivergenceCause::AsBoundaryPolicy { from_asn, to_asn } => {
                    println!("  → Divergence at AS{} → AS{} boundary.", from_asn, to_asn);
                    println!("    The border router enforces per-protocol routing policy.");
                    println!("    (Common at peering/transit points — BGP community tags)");
                }
                DivergenceCause::IntraAsPolicy { asn } => {
                    println!("  → Divergence within AS{}.", asn);
                    println!("    An internal device treats protocols differently.");
                    println!("    (Firewall ACL, ECMP hash, or QoS classification)");
                }
                DivergenceCause::CloudProviderEdge { provider_name, provider_asn } => {
                    println!("  → Cloud provider edge (AS{}, {}).", provider_asn, provider_name);
                    println!("    Protocol steering common at cloud CDN/load balancer edge.");
                }
                DivergenceCause::TransitProvider { transit_asn } => {
                    println!("  → Transit provider AS{} is steering traffic.", transit_asn);
                }
                DivergenceCause::Unknown => {
                    println!("  → Could not determine cause (private IPs or lookup failure).");
                }
            }

            // ── AS path and stats ─────────────────────────────────────────────
            if !result.as_path.is_empty() {
                println!("\n  AS Path ({} transitions): {}",
                    result.as_transitions,
                    result.as_path_str());
            }

            if let Some(hop) = result.first_divergence_hop {
                println!("  First divergence:  hop {}", hop);
            } else {
                println!("  No protocol divergence detected on this path.");
            }

            println!("\n  Total analysis time: {:.2}s", result.total_time.as_secs_f64());
        }
        Err(e) => {
            eprintln!("\n  Error: {}", e);
            if e.to_string().to_lowercase().contains("permission")
                || e.to_string().to_lowercase().contains("denied")
                || e.to_string().to_lowercase().contains("operation not permitted")
            {
                eprintln!("  → Requires elevated privileges:");
                eprintln!("    sudo cargo run --example bgp_correlation {}", target);
            }
        }
    }

    Ok(())
}
