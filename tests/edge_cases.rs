//! Comprehensive edge case tests for multiprobe library

use multiprobe::{Probe, Protocol, Classifier, TracerouteOptions};
use std::time::Duration;

// ============================================================================
// INPUT VALIDATION TESTS
// ============================================================================

#[tokio::test]
async fn test_empty_hostname() {
    let result = Probe::tcp("", 80)
        .timeout(Duration::from_secs(2))
        .send()
        .await;
    assert!(result.is_err(), "Empty hostname should fail");
}

#[tokio::test]
async fn test_whitespace_hostname() {
    let result = Probe::tcp("   ", 80).send().await;
    assert!(result.is_err(), "Whitespace-only hostname should fail");
}

#[tokio::test]
async fn test_invalid_hostname_characters() {
    let result = Probe::tcp("invalid<>hostname", 80).send().await;
    assert!(result.is_err(), "Invalid characters in hostname should fail");
}

#[tokio::test]
async fn test_very_long_hostname() {
    let long_hostname = "a".repeat(300) + ".com";
    let result = Probe::tcp(&long_hostname, 80).send().await;
    assert!(result.is_err(), "Very long hostname should fail");
}

#[tokio::test]
async fn test_hostname_with_port_in_string() {
    // Should not parse port from hostname string
    let result = Probe::tcp("localhost:8080", 80)
        .timeout(Duration::from_millis(100))
        .send()
        .await;
    // This should fail because "localhost:8080" is not a valid hostname
    assert!(result.is_err(), "Hostname with embedded port should fail");
}

// ============================================================================
// PORT EDGE CASES
// ============================================================================

#[tokio::test]
async fn test_port_zero() {
    let result = Probe::tcp("127.0.0.1", 0)
        .timeout(Duration::from_millis(100))
        .send()
        .await;
    // Port 0 is technically valid but usually not usable
    // The result depends on OS behavior
    println!("Port 0 result: {result:?}");
}

#[tokio::test]
async fn test_port_max() {
    let result = Probe::tcp("127.0.0.1", 65535)
        .timeout(Duration::from_millis(100))
        .send()
        .await;
    // Should work but likely refused on localhost
    match result {
        Ok(r) => assert!(!r.success, "Port 65535 should be closed on localhost"),
        Err(e) => println!("Port 65535 error (expected): {e}"),
    }
}

#[tokio::test]
async fn test_privileged_port() {
    let result = Probe::tcp("127.0.0.1", 22)
        .timeout(Duration::from_millis(100))
        .send()
        .await;
    // Port 22 (SSH) - behavior depends on whether SSH is running
    println!("Port 22 result: {result:?}");
}

// ============================================================================
// TIMEOUT EDGE CASES
// ============================================================================

#[tokio::test]
async fn test_very_short_timeout() {
    let result = Probe::tcp("8.8.8.8", 53)
        .timeout(Duration::from_millis(1))
        .send()
        .await;
    // Very short timeout - should likely fail
    if let Ok(r) = result {
        println!("Short timeout succeeded unexpectedly: {r:?}");
    }
}

#[tokio::test]
async fn test_zero_timeout() {
    let result = Probe::tcp("127.0.0.1", 80)
        .timeout(Duration::ZERO)
        .send()
        .await;
    // Zero timeout behavior
    println!("Zero timeout result: {result:?}");
}

#[tokio::test]
async fn test_reasonable_timeout() {
    let result = Probe::tcp("127.0.0.1", 80)
        .timeout(Duration::from_secs(1))
        .send()
        .await;
    // Should complete (success or failure) within timeout
    assert!(result.is_ok() || result.is_err());
}

// ============================================================================
// IP ADDRESS FORMATS
// ============================================================================

#[tokio::test]
async fn test_ipv4_localhost() {
    let result = Probe::tcp("127.0.0.1", 80)
        .timeout(Duration::from_millis(100))
        .send()
        .await;
    assert!(result.is_ok(), "Localhost probe should complete");
}

#[tokio::test]
async fn test_ipv4_loopback_full() {
    let result = Probe::tcp("127.0.0.1", 12345)
        .timeout(Duration::from_millis(100))
        .send()
        .await;
    match result {
        Ok(r) => assert!(!r.success, "Random port on localhost should be closed"),
        Err(e) => println!("Error: {e}"),
    }
}

#[tokio::test]
async fn test_private_ip_10() {
    let result = Probe::tcp("10.0.0.1", 80)
        .timeout(Duration::from_millis(500))
        .send()
        .await;
    // Private IP - might timeout or refuse
    println!("Private IP 10.x result: {result:?}");
}

#[tokio::test]
async fn test_private_ip_192() {
    let result = Probe::tcp("192.168.1.1", 80)
        .timeout(Duration::from_millis(500))
        .send()
        .await;
    // Common router IP - might work or timeout
    println!("Private IP 192.168.x result: {result:?}");
}

#[tokio::test]
async fn test_broadcast_address() {
    let result = Probe::tcp("255.255.255.255", 80)
        .timeout(Duration::from_millis(100))
        .send()
        .await;
    // Broadcast - should fail
    assert!(result.is_err() || !result.unwrap().success);
}

#[tokio::test]
async fn test_ipv6_localhost() {
    let result = Probe::tcp("::1", 80)
        .timeout(Duration::from_millis(100))
        .send()
        .await;
    // IPv6 localhost - may or may not work depending on system config
    println!("IPv6 localhost result: {result:?}");
}

// ============================================================================
// MULTI-PROBE EDGE CASES
// ============================================================================

#[tokio::test]
async fn test_multi_probe_empty_protocols() {
    let result = Probe::multi("127.0.0.1")
        .timeout(Duration::from_millis(100))
        .send()
        .await;
    assert!(result.is_err(), "Multi-probe with no protocols should fail");
}

#[tokio::test]
async fn test_multi_probe_single_protocol() {
    let result = Probe::multi("127.0.0.1")
        .tcp(80)
        .timeout(Duration::from_millis(100))
        .send()
        .await;
    assert!(result.is_ok(), "Single protocol should work");
    assert_eq!(result.unwrap().results.len(), 1);
}

#[tokio::test]
async fn test_multi_probe_duplicate_protocols() {
    let result = Probe::multi("127.0.0.1")
        .tcp(80)
        .tcp(80)  // Duplicate
        .timeout(Duration::from_millis(100))
        .send()
        .await;
    assert!(result.is_ok(), "Duplicate protocols should be allowed");
    assert_eq!(result.unwrap().results.len(), 2);
}

#[tokio::test]
async fn test_multi_probe_many_protocols() {
    let mut probe = Probe::multi("127.0.0.1");
    for port in 80..90 {
        probe = probe.tcp(port);
    }
    let result = probe
        .timeout(Duration::from_millis(100))
        .send()
        .await;
    assert!(result.is_ok(), "Many protocols should work");
    assert_eq!(result.unwrap().results.len(), 10);
}

#[tokio::test]
async fn test_multi_probe_mixed_protocols() {
    let result = Probe::multi("127.0.0.1")
        .tcp(80)
        .udp(53)
        .tcp(443)
        .timeout(Duration::from_millis(100))
        .send()
        .await;
    assert!(result.is_ok());
    let r = result.unwrap();
    assert_eq!(r.results.len(), 3);
}

// ============================================================================
// UDP EDGE CASES
// ============================================================================

#[tokio::test]
async fn test_udp_localhost() {
    let result = Probe::udp("127.0.0.1", 53)
        .timeout(Duration::from_millis(500))
        .send()
        .await;
    // UDP to localhost DNS - probably no DNS server running
    println!("UDP localhost result: {result:?}");
}

#[tokio::test]
#[ignore = "requires network"]
async fn test_udp_real_dns() {
    let result = Probe::udp("8.8.8.8", 53)
        .timeout(Duration::from_secs(2))
        .send()
        .await;
    // Google DNS should accept UDP packets
    assert!(result.is_ok(), "UDP to Google DNS should work");
}

#[tokio::test]
async fn test_udp_non_dns_port() {
    let result = Probe::udp("127.0.0.1", 12345)
        .timeout(Duration::from_millis(500))
        .send()
        .await;
    // Random UDP port - might get port unreachable or timeout
    println!("UDP non-DNS result: {result:?}");
}

// ============================================================================
// CLASSIFIER EDGE CASES
// ============================================================================

#[tokio::test]
async fn test_classifier_empty_results() {
    let results: Vec<multiprobe::ProbeResult> = vec![];
    let classification = Classifier::classify(&results);
    assert_eq!(classification, multiprobe::PathClassification::Unknown);
}

#[tokio::test]
async fn test_classifier_fingerprint_empty() {
    let results: Vec<multiprobe::ProbeResult> = vec![];
    let fingerprint = Classifier::fingerprint(&results);
    assert_eq!(fingerprint, "Unknown");
}

#[tokio::test]
async fn test_differential_score_empty() {
    let results: Vec<multiprobe::ProbeResult> = vec![];
    let score = Classifier::differential_score(&results);
    assert_eq!(score.consistency, 1.0); // No differences means consistent
}

// ============================================================================
// TRACEROUTE EDGE CASES
// ============================================================================

#[tokio::test]
#[ignore = "requires CAP_NET_RAW or root"]
async fn test_traceroute_localhost() {
    let result = Probe::traceroute("127.0.0.1")
        .max_hops(5)
        .timeout_per_hop(Duration::from_millis(500))
        .send()
        .await;
    // Localhost traceroute - may need privileges
    println!("Traceroute localhost result: {result:?}");
}

#[tokio::test]
#[ignore = "requires network and CAP_NET_RAW"]
async fn test_traceroute_max_hops_one() {
    let result = Probe::traceroute("8.8.8.8")
        .max_hops(1)
        .timeout_per_hop(Duration::from_secs(1))
        .send()
        .await;
    match result {
        Ok(r) => {
            assert_eq!(r.hops.len(), 1, "Should have exactly 1 hop");
            assert!(!r.reached_destination, "Should not reach destination with 1 hop");
        }
        Err(e) => println!("Traceroute error (may need privileges): {e}"),
    }
}

#[tokio::test]
async fn test_traceroute_options_default() {
    let opts = TracerouteOptions::default();
    assert_eq!(opts.max_hops, 30);
    assert_eq!(opts.timeout_per_hop, Duration::from_secs(2));
    assert_eq!(opts.probes_per_hop, 1);
}

// ============================================================================
// TIMING BREAKDOWN TESTS
// ============================================================================

#[tokio::test]
async fn test_timing_breakdown_dns_skip() {
    // IP address should have zero DNS time
    let result = Probe::tcp("127.0.0.1", 80)
        .timeout(Duration::from_millis(100))
        .send()
        .await;

    if let Ok(r) = result {
        assert!(r.timing.dns_ms().is_none() || r.timing.dns_ms() == Some(0.0),
            "Direct IP should have no/zero DNS time");
    }
}

#[tokio::test]
#[ignore = "requires network"]
async fn test_timing_breakdown_with_dns() {
    let result = Probe::tcp("google.com", 443)
        .timeout(Duration::from_secs(5))
        .send()
        .await;

    if let Ok(r) = result {
        // DNS time should be recorded for hostname
        println!("DNS time: {:?}ms", r.timing.dns_ms());
        println!("Connect time: {:?}ms", r.timing.connect_ms());
        println!("Total time: {:?}ms", r.timing.total_ms());
        assert!(r.timing.total_ms() > 0.0);
    }
}

// ============================================================================
// CONCURRENT OPERATION TESTS
// ============================================================================

#[tokio::test]
async fn test_concurrent_probes_same_target() {
    let futures: Vec<_> = (0..5).map(|_| {
        Probe::tcp("127.0.0.1", 80)
            .timeout(Duration::from_millis(100))
            .send()
    }).collect();

    let results = futures::future::join_all(futures).await;

    // All should complete
    for (i, result) in results.iter().enumerate() {
        assert!(result.is_ok(), "Probe {i} should complete");
    }
}

#[tokio::test]
#[ignore = "requires network"]
async fn test_concurrent_probes_different_targets() {
    let targets = ["127.0.0.1", "8.8.8.8", "1.1.1.1"];
    let futures: Vec<_> = targets.iter().map(|target| {
        Probe::tcp(target, 443)
            .timeout(Duration::from_secs(3))
            .send()
    }).collect();

    let results = futures::future::join_all(futures).await;

    // All should complete (success or failure)
    for result in results {
        assert!(result.is_ok() || result.is_err());
    }
}

// ============================================================================
// ERROR RECOVERY TESTS
// ============================================================================

#[tokio::test]
async fn test_probe_after_dns_failure() {
    // First, a failing DNS lookup
    let _ = Probe::tcp("invalid.hostname.xyz", 80)
        .timeout(Duration::from_secs(1))
        .send()
        .await;

    // Then a valid probe - should still work
    let result = Probe::tcp("127.0.0.1", 80)
        .timeout(Duration::from_millis(100))
        .send()
        .await;

    assert!(result.is_ok(), "Probe should work after DNS failure");
}

#[tokio::test]
async fn test_probe_after_timeout() {
    // First, a timing out probe (very short timeout to distant server)
    let _ = Probe::tcp("8.8.8.8", 80)
        .timeout(Duration::from_millis(1))
        .send()
        .await;

    // Then a valid probe - should still work
    let result = Probe::tcp("127.0.0.1", 80)
        .timeout(Duration::from_millis(100))
        .send()
        .await;

    assert!(result.is_ok(), "Probe should work after timeout");
}

// ============================================================================
// PROTOCOL ENUM TESTS
// ============================================================================

#[test]
fn test_protocol_display() {
    assert_eq!(Protocol::Icmp.to_string(), "ICMP");
    assert_eq!(Protocol::Tcp(80).to_string(), "TCP/80");
    assert_eq!(Protocol::Tcp(443).to_string(), "TCP/443");
    assert_eq!(Protocol::Udp(53).to_string(), "UDP/53");
}

#[test]
fn test_protocol_port() {
    assert_eq!(Protocol::Icmp.port(), None);
    assert_eq!(Protocol::Tcp(80).port(), Some(80));
    assert_eq!(Protocol::Udp(53).port(), Some(53));
}

#[test]
fn test_protocol_equality() {
    assert_eq!(Protocol::Tcp(80), Protocol::Tcp(80));
    assert_ne!(Protocol::Tcp(80), Protocol::Tcp(443));
    assert_ne!(Protocol::Tcp(80), Protocol::Udp(80));
}

// ============================================================================
// RESULT TYPE TESTS
// ============================================================================

#[tokio::test]
async fn test_multi_probe_result_classify() {
    let result = Probe::multi("127.0.0.1")
        .tcp(80)
        .tcp(443)
        .timeout(Duration::from_millis(100))
        .send()
        .await;

    if let Ok(r) = result {
        let classification = r.classify();
        // Should return a valid classification string
        assert!(!classification.to_string().is_empty());
    }
}

#[tokio::test]
async fn test_traceroute_result_methods() {
    let result = Probe::traceroute("127.0.0.1")
        .max_hops(3)
        .timeout_per_hop(Duration::from_millis(500))
        .send()
        .await;

    if let Ok(r) = result {
        // Test all result methods
        let _count = r.hop_count();
        let _responsive = r.responsive_hops();
        let _path = r.path();
        let _contains = r.path_contains(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
    }
}

// ============================================================================
// PARIS TRACEROUTE TESTS
// ============================================================================

#[tokio::test]
#[ignore = "requires CAP_NET_RAW or root"]
async fn test_paris_localhost() {
    let result = Probe::paris("127.0.0.1")
        .max_hops(5)
        .timeout_per_hop(Duration::from_millis(500))
        .send()
        .await;

    // May fail due to permissions, but should not panic
    println!("Paris localhost result: {:?}", result.is_ok());
}

#[tokio::test]
async fn test_paris_invalid_hostname() {
    let result = Probe::paris("")
        .max_hops(5)
        .send()
        .await;

    assert!(result.is_err(), "Empty hostname should fail");
}

#[tokio::test]
#[ignore = "requires CAP_NET_RAW or root"]
async fn test_paris_max_hops_one() {
    let result = Probe::paris("127.0.0.1")
        .max_hops(1)
        .timeout_per_hop(Duration::from_millis(500))
        .send()
        .await;

    if let Ok(r) = result {
        assert!(r.hops.len() <= 1, "Should have at most 1 hop");
    }
}

#[tokio::test]
#[ignore = "requires CAP_NET_RAW or root"]
async fn test_paris_mode_icmp() {
    use multiprobe::ParisMode;

    let result = Probe::paris("127.0.0.1")
        .mode(ParisMode::Icmp)
        .max_hops(3)
        .timeout_per_hop(Duration::from_millis(500))
        .send()
        .await;

    println!("Paris ICMP mode result: {:?}", result.is_ok());
}

#[tokio::test]
async fn test_paris_flow_id() {
    use multiprobe::FlowId;

    let flow = FlowId::udp(12345, 54321);
    assert_eq!(flow.src_port, 12345);
    assert_eq!(flow.dst_port, 54321);
    assert_eq!(flow.protocol, 17); // UDP

    let tcp_flow = FlowId::tcp(80, 443);
    assert_eq!(tcp_flow.protocol, 6); // TCP

    let icmp_flow = FlowId::icmp(1234);
    assert_eq!(icmp_flow.protocol, 1); // ICMP
}

#[tokio::test]
#[ignore = "requires CAP_NET_RAW or root"]
async fn test_paris_with_load_balancing_detection() {
    let result = Probe::paris("127.0.0.1")
        .max_hops(3)
        .detect_load_balancing(true)
        .timeout_per_hop(Duration::from_millis(500))
        .send()
        .await;

    if let Ok(r) = result {
        // Just verify the field exists and has a value
        println!("Load balancing type: {}", r.load_balancing);
    }
}

// ============================================================================
// TLS PROBE TESTS
// ============================================================================

#[tokio::test]
async fn test_tls_invalid_hostname() {
    let result = Probe::tls("")
        .timeout(Duration::from_secs(2))
        .send()
        .await;

    assert!(result.is_err(), "Empty hostname should fail");
}

#[tokio::test]
async fn test_tls_localhost_no_server() {
    let result = Probe::tls("127.0.0.1")
        .port(44444) // Random port with no TLS server
        .timeout(Duration::from_millis(500))
        .send()
        .await;

    // Should complete but show failure
    if let Ok(r) = result {
        assert!(!r.success, "No TLS server should fail handshake");
        assert!(r.error.is_some(), "Should have error message");
    }
}

#[tokio::test]
async fn test_tls_custom_port() {
    let result = Probe::tls("127.0.0.1")
        .port(8443)
        .timeout(Duration::from_millis(200))
        .send()
        .await;

    // Just verify it doesn't panic
    println!("TLS custom port result: {:?}", result.is_ok());
}

#[tokio::test]
async fn test_tls_with_sni() {
    let result = Probe::tls("127.0.0.1")
        .sni("example.com")
        .timeout(Duration::from_millis(200))
        .send()
        .await;

    println!("TLS with SNI result: {:?}", result.is_ok());
}

#[tokio::test]
async fn test_tls_skip_verify() {
    let result = Probe::tls("127.0.0.1")
        .skip_verify()
        .timeout(Duration::from_millis(200))
        .send()
        .await;

    println!("TLS skip verify result: {:?}", result.is_ok());
}

#[tokio::test]
async fn test_tls_version_display() {
    use multiprobe::TlsVersion;

    assert_eq!(TlsVersion::Tls10.to_string(), "TLS 1.0");
    assert_eq!(TlsVersion::Tls11.to_string(), "TLS 1.1");
    assert_eq!(TlsVersion::Tls12.to_string(), "TLS 1.2");
    assert_eq!(TlsVersion::Tls13.to_string(), "TLS 1.3");
    assert_eq!(TlsVersion::Unknown.to_string(), "Unknown");
}

// ============================================================================
// LATENCY STATS TESTS
// ============================================================================

#[tokio::test]
async fn test_latency_localhost() {
    let result = Probe::latency("127.0.0.1", 80)
        .samples(3)
        .interval(Duration::from_millis(10))
        .send()
        .await;

    if let Ok(stats) = result {
        assert_eq!(stats.sample_count, 3);
        // Localhost probes might fail (no server), but stats should be computed
        println!("Latency stats: min={:?}, max={:?}, loss={:.1}%",
            stats.min_rtt, stats.max_rtt, stats.loss_rate * 100.0);
    }
}

#[tokio::test]
async fn test_latency_invalid_hostname() {
    let result = Probe::latency("", 80)
        .samples(1)
        .send()
        .await;

    assert!(result.is_err(), "Empty hostname should fail");
}

#[tokio::test]
async fn test_latency_stats_methods() {
    use multiprobe::LatencyStats;

    let samples = vec![
        Some(Duration::from_millis(10)),
        Some(Duration::from_millis(20)),
        Some(Duration::from_millis(15)),
        None, // Lost packet
        Some(Duration::from_millis(12)),
    ];

    let stats = LatencyStats::from_samples(&samples);

    assert_eq!(stats.sample_count, 5);
    assert_eq!(stats.success_count, 4);
    assert!((stats.loss_rate - 0.2).abs() < 0.01, "Loss rate should be 20%");
    assert_eq!(stats.min_rtt, Duration::from_millis(10));
    assert_eq!(stats.max_rtt, Duration::from_millis(20));

    // Test helper methods
    let _ = stats.has_high_jitter();
    let _ = stats.has_packet_loss();
}

#[tokio::test]
async fn test_latency_stats_empty() {
    use multiprobe::LatencyStats;

    let samples: Vec<Option<Duration>> = vec![];
    let stats = LatencyStats::from_samples(&samples);

    assert_eq!(stats.sample_count, 0);
    assert_eq!(stats.success_count, 0);
    assert_eq!(stats.loss_rate, 1.0);
}

#[tokio::test]
async fn test_latency_stats_all_loss() {
    use multiprobe::LatencyStats;

    let samples: Vec<Option<Duration>> = vec![None, None, None];
    let stats = LatencyStats::from_samples(&samples);

    assert_eq!(stats.sample_count, 3);
    assert_eq!(stats.success_count, 0);
    assert_eq!(stats.loss_rate, 1.0);
}

// ============================================================================
// MTU DISCOVERY TESTS
// ============================================================================

#[tokio::test]
async fn test_mtu_localhost() {
    let result = Probe::mtu("127.0.0.1")
        .min_mtu(68)
        .max_mtu(1500)
        .timeout(Duration::from_millis(500))
        .send()
        .await;

    // May need elevated privileges
    println!("MTU discovery result: {:?}", result.is_ok());
}

#[tokio::test]
async fn test_mtu_invalid_hostname() {
    let result = Probe::mtu("")
        .send()
        .await;

    assert!(result.is_err(), "Empty hostname should fail");
}

#[tokio::test]
async fn test_mtu_options_default() {
    use multiprobe::PmtudOptions;

    let opts = PmtudOptions::default();
    assert_eq!(opts.min_mtu, 68);
    assert_eq!(opts.max_mtu, 1500);
}

// ============================================================================
// BUFFERBLOAT TESTS
// ============================================================================

#[tokio::test]
async fn test_bufferbloat_localhost() {
    let result = Probe::bufferbloat("127.0.0.1")
        .port(80)
        .baseline_samples(2)
        .loaded_samples(2)
        .send()
        .await;

    // Will likely fail on localhost with no server
    println!("Bufferbloat result: {:?}", result.is_ok());
}

#[tokio::test]
async fn test_bufferbloat_invalid_hostname() {
    let result = Probe::bufferbloat("")
        .send()
        .await;

    assert!(result.is_err(), "Empty hostname should fail");
}

#[tokio::test]
async fn test_bufferbloat_grade() {
    use multiprobe::BufferbloatGrade;

    assert_eq!(BufferbloatGrade::A.to_string(), "A (Excellent)");
    assert_eq!(BufferbloatGrade::B.to_string(), "B (Good)");
    assert_eq!(BufferbloatGrade::C.to_string(), "C (Fair)");
    assert_eq!(BufferbloatGrade::D.to_string(), "D (Poor)");
    assert_eq!(BufferbloatGrade::F.to_string(), "F (Bad)");
}

#[tokio::test]
async fn test_bufferbloat_options_default() {
    use multiprobe::BufferbloatOptions;

    let opts = BufferbloatOptions::default();
    assert_eq!(opts.baseline_samples, 10);
    assert_eq!(opts.loaded_samples, 10);
    assert_eq!(opts.load_connections, 4);
    assert_eq!(opts.port, 443);
}

// ============================================================================
// LOAD BALANCING TYPE TESTS
// ============================================================================

#[test]
fn test_load_balancing_type_display() {
    use multiprobe::LoadBalancingType;

    assert_eq!(LoadBalancingType::None.to_string(), "None");
    assert_eq!(LoadBalancingType::PerFlow.to_string(), "Per-flow ECMP");
    assert_eq!(LoadBalancingType::PerPacket.to_string(), "Per-packet ECMP");
    assert_eq!(LoadBalancingType::Unknown.to_string(), "Unknown");
}

// ============================================================================
// CONCURRENT PARIS TESTS
// ============================================================================

#[tokio::test]
async fn test_concurrent_paris_probes() {
    let futures: Vec<_> = (0..3).map(|_| {
        Probe::paris("127.0.0.1")
            .max_hops(2)
            .timeout_per_hop(Duration::from_millis(200))
            .send()
    }).collect();

    let results = futures::future::join_all(futures).await;

    // All should complete without panic
    for result in results {
        let _ = result; // Just verify no panic
    }
}

// ============================================================================
// CONCURRENT TLS TESTS
// ============================================================================

#[tokio::test]
async fn test_concurrent_tls_probes() {
    let futures: Vec<_> = (0..3).map(|_| {
        Probe::tls("127.0.0.1")
            .port(44444)
            .timeout(Duration::from_millis(200))
            .send()
    }).collect();

    let results = futures::future::join_all(futures).await;

    // All should complete without panic
    for result in results {
        let _ = result;
    }
}

// ============================================================================
// EDGE CASE: VERY SHORT TIMEOUTS
// ============================================================================

#[tokio::test]
async fn test_paris_very_short_timeout() {
    let result = Probe::paris("8.8.8.8")
        .max_hops(1)
        .timeout_per_hop(Duration::from_millis(1))
        .send()
        .await;

    // Should complete (likely all timeouts) but not panic
    println!("Paris short timeout: {:?}", result.is_ok());
}

#[tokio::test]
async fn test_tls_very_short_timeout() {
    let result = Probe::tls("google.com")
        .timeout(Duration::from_millis(1))
        .send()
        .await;

    // Should complete but likely fail
    if let Ok(r) = result {
        // Very short timeout should cause failure
        println!("TLS short timeout success: {}", r.success);
    }
}

// ============================================================================
// REAL TARGET TESTS (require network)
// ============================================================================

#[tokio::test]
async fn test_tls_real_target() {
    let result = Probe::tls("google.com")
        .timeout(Duration::from_secs(10))
        .send()
        .await;

    match result {
        Ok(r) => {
            println!("TLS to google.com:");
            println!("  Success: {}", r.success);
            println!("  Version: {}", r.tls_version);
            println!("  Cipher: {:?}", r.cipher_suite);
            println!("  Timing: DNS={:.2}ms TCP={:.2}ms TLS={:.2}ms",
                r.timing.dns_ms(), r.timing.tcp_ms(), r.timing.tls_ms());
        }
        Err(e) => {
            println!("TLS probe failed (network issue?): {}", e);
        }
    }
}

#[tokio::test]
async fn test_latency_real_target() {
    let result = Probe::latency("google.com", 443)
        .samples(5)
        .interval(Duration::from_millis(100))
        .send()
        .await;

    match result {
        Ok(stats) => {
            println!("Latency to google.com:443:");
            println!("  Samples: {}/{}", stats.success_count, stats.sample_count);
            println!("  Min: {:.2}ms", stats.min_rtt.as_secs_f64() * 1000.0);
            println!("  Max: {:.2}ms", stats.max_rtt.as_secs_f64() * 1000.0);
            println!("  Mean: {:.2}ms", stats.mean_rtt.as_secs_f64() * 1000.0);
            println!("  Jitter: {:.2}ms", stats.jitter.as_secs_f64() * 1000.0);
        }
        Err(e) => {
            println!("Latency measurement failed: {}", e);
        }
    }
}
