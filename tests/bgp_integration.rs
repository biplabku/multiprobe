//! Integration tests for BGP correlation module
//!
//! These tests verify ASN lookups work against real DNS services.

use std::net::{IpAddr, Ipv4Addr};
use multiprobe::bgp::AsnLookup;

#[tokio::test]
async fn test_asn_lookup_major_providers() {
    let lookup = AsnLookup::new().await.expect("Failed to create ASN lookup");

    // Test well-known IPs with expected ASNs
    let test_cases = vec![
        (Ipv4Addr::new(8, 8, 8, 8), 15169, "Google"),
        (Ipv4Addr::new(1, 1, 1, 1), 13335, "Cloudflare"),
    ];

    for (ip, expected_asn, provider) in test_cases {
        let result = lookup.lookup(IpAddr::V4(ip)).await;

        match result {
            Ok(info) => {
                assert_eq!(info.asn, expected_asn,
                    "{} ({}) should be AS{}, got AS{}",
                    ip, provider, expected_asn, info.asn);
                println!("✓ {} -> AS{} ({})", ip, info.asn,
                    info.as_name.as_deref().unwrap_or("unknown"));
            }
            Err(e) => {
                println!("⚠ {} lookup failed (network issue?): {}", ip, e);
            }
        }
    }
}

#[tokio::test]
async fn test_asn_cache_effectiveness() {
    let lookup = AsnLookup::new().await.expect("Failed to create ASN lookup");
    let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

    // First lookup
    let _ = lookup.lookup(ip).await;
    let cache_size_after_first = lookup.cache_size().await;

    // Second lookup (should hit cache)
    let _ = lookup.lookup(ip).await;
    let cache_size_after_second = lookup.cache_size().await;

    // Cache should not grow for repeated lookups
    assert_eq!(cache_size_after_first, cache_size_after_second);
    assert_eq!(cache_size_after_first, 1);
    println!("✓ Cache working: size={}", cache_size_after_first);
}

#[tokio::test]
async fn test_cloud_provider_detection() {
    let lookup = AsnLookup::new().await.expect("Failed to create ASN lookup");

    let cloud_ips = vec![
        (Ipv4Addr::new(8, 8, 8, 8), true, "Google"),       // AS15169
        (Ipv4Addr::new(1, 1, 1, 1), true, "Cloudflare"),   // AS13335
    ];

    for (ip, expected_cloud, provider) in cloud_ips {
        if let Ok(info) = lookup.lookup(IpAddr::V4(ip)).await {
            let is_cloud = info.is_cloud_provider();
            assert_eq!(is_cloud, expected_cloud,
                "{} ({}) cloud detection: expected={}, got={}",
                ip, provider, expected_cloud, is_cloud);
            println!("✓ {} is_cloud_provider={} (AS{})", ip, is_cloud, info.asn);
        }
    }
}

#[tokio::test]
async fn test_transit_provider_detection() {
    let lookup = AsnLookup::new().await.expect("Failed to create ASN lookup");

    // Google and Cloudflare are content providers, not transit
    let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    if let Ok(info) = lookup.lookup(ip).await {
        assert!(!info.is_transit(), "Google should not be a transit provider");
        println!("✓ AS15169 (Google) is_transit=false");
    }
}

#[tokio::test]
async fn test_batch_lookup() {
    let lookup = AsnLookup::new().await.expect("Failed to create ASN lookup");

    let ips = vec![
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), // Private - should error
    ];

    let results = lookup.lookup_batch(&ips).await;

    assert_eq!(results.len(), 3);

    // Public IPs should succeed
    assert!(results.get(&ips[0]).unwrap().is_ok());
    assert!(results.get(&ips[1]).unwrap().is_ok());

    // Private IP should fail
    assert!(results.get(&ips[2]).unwrap().is_err());

    println!("✓ Batch lookup: {} results", results.len());
}
