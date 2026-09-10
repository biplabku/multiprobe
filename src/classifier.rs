//! Path classification based on multi-protocol probe results
//!
//! Implements Protocol Differential Analysis for network path fingerprinting.

use crate::types::{PathClassification, ProbeResult, Protocol};

/// Protocol Differential Score - quantifies behavioral differences across protocols
#[derive(Debug, Clone, Default)]
pub struct ProtocolDifferentialScore {
    /// ICMP vs TCP differential (0.0 = identical, 1.0 = completely different)
    pub icmp_tcp_diff: f64,
    /// ICMP vs UDP differential
    pub icmp_udp_diff: f64,
    /// TCP vs UDP differential
    pub tcp_udp_diff: f64,
    /// Overall path consistency score (0.0 = inconsistent, 1.0 = consistent)
    pub consistency: f64,
    /// Latency variance across protocols
    pub latency_variance_ms: f64,
}

impl ProtocolDifferentialScore {
    /// Calculate the Protocol Differential Score from probe results
    pub fn calculate(results: &[ProbeResult]) -> Self {
        let icmp_success = results.iter()
            .filter(|r| matches!(r.protocol, Protocol::Icmp))
            .map(|r| if r.success { 1.0 } else { 0.0 })
            .next();

        let tcp_success_rate = Self::success_rate(results, |p| matches!(p, Protocol::Tcp(_)));
        let udp_success_rate = Self::success_rate(results, |p| matches!(p, Protocol::Udp(_)));

        let icmp_tcp_diff = match icmp_success {
            Some(icmp) if tcp_success_rate.is_some() => {
                (icmp - tcp_success_rate.unwrap()).abs()
            }
            _ => 0.0,
        };

        let icmp_udp_diff = match icmp_success {
            Some(icmp) if udp_success_rate.is_some() => {
                (icmp - udp_success_rate.unwrap()).abs()
            }
            _ => 0.0,
        };

        let tcp_udp_diff = match (tcp_success_rate, udp_success_rate) {
            (Some(tcp), Some(udp)) => (tcp - udp).abs(),
            _ => 0.0,
        };

        // Calculate consistency: 1.0 if all protocols behave the same
        let total_diff = icmp_tcp_diff + icmp_udp_diff + tcp_udp_diff;
        let consistency = 1.0 - (total_diff / 3.0).min(1.0);

        // Calculate latency variance
        let latencies: Vec<f64> = results.iter()
            .filter(|r| r.success)
            .map(|r| r.timing.total_ms())
            .collect();

        let latency_variance_ms = if latencies.len() >= 2 {
            let mean = latencies.iter().sum::<f64>() / latencies.len() as f64;
            let variance = latencies.iter()
                .map(|l| (l - mean).powi(2))
                .sum::<f64>() / latencies.len() as f64;
            variance.sqrt()
        } else {
            0.0
        };

        Self {
            icmp_tcp_diff,
            icmp_udp_diff,
            tcp_udp_diff,
            consistency,
            latency_variance_ms,
        }
    }

    fn success_rate<F>(results: &[ProbeResult], filter: F) -> Option<f64>
    where
        F: Fn(&Protocol) -> bool,
    {
        let matching: Vec<_> = results.iter()
            .filter(|r| filter(&r.protocol))
            .collect();

        if matching.is_empty() {
            None
        } else {
            let success_count = matching.iter().filter(|r| r.success).count();
            Some(success_count as f64 / matching.len() as f64)
        }
    }

    /// Interpret the score as a network behavior type
    pub fn interpret(&self) -> NetworkBehavior {
        if self.consistency > 0.9
            && self.icmp_tcp_diff < 0.1 && self.tcp_udp_diff < 0.1 {
                return NetworkBehavior::Direct;
            }

        if self.icmp_tcp_diff > 0.5 && self.icmp_udp_diff > 0.5 {
            return NetworkBehavior::IcmpFiltering;
        }

        if self.tcp_udp_diff > 0.5 {
            return NetworkBehavior::ProtocolSpecificFiltering;
        }

        if self.latency_variance_ms > 50.0 {
            return NetworkBehavior::AsymmetricRouting;
        }

        NetworkBehavior::Unknown
    }
}

/// Detected network behavior based on protocol analysis
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkBehavior {
    /// Direct path - all protocols behave consistently
    Direct,
    /// ICMP is filtered while TCP/UDP pass
    IcmpFiltering,
    /// Protocol-specific filtering (TCP vs UDP treated differently)
    ProtocolSpecificFiltering,
    /// Asymmetric routing detected (high latency variance)
    AsymmetricRouting,
    /// Unable to determine
    Unknown,
}

impl std::fmt::Display for NetworkBehavior {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkBehavior::Direct => write!(f, "Direct path"),
            NetworkBehavior::IcmpFiltering => write!(f, "ICMP filtering"),
            NetworkBehavior::ProtocolSpecificFiltering => write!(f, "Protocol-specific filtering"),
            NetworkBehavior::AsymmetricRouting => write!(f, "Asymmetric routing"),
            NetworkBehavior::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Classifier for network path behavior based on probe results
pub struct Classifier;

impl Classifier {
    /// Classify a path based on multi-protocol probe results
    pub fn classify(results: &[ProbeResult]) -> PathClassification {
        if results.is_empty() {
            return PathClassification::Unknown;
        }

        let icmp_results: Vec<_> = results.iter()
            .filter(|r| matches!(r.protocol, Protocol::Icmp))
            .collect();
        let icmp_success = icmp_results.iter().any(|r| r.success);
        let has_icmp = !icmp_results.is_empty();

        let tcp_results: Vec<_> = results.iter()
            .filter(|r| matches!(r.protocol, Protocol::Tcp(_)))
            .collect();

        let udp_results: Vec<_> = results.iter()
            .filter(|r| matches!(r.protocol, Protocol::Udp(_)))
            .collect();

        let tcp_success_count = tcp_results.iter().filter(|r| r.success).count();
        let udp_success_count = udp_results.iter().filter(|r| r.success).count();

        let any_tcp = !tcp_results.is_empty();
        let any_udp = !udp_results.is_empty();
        let any_tcp_success = tcp_success_count > 0;
        let any_udp_success = udp_success_count > 0;

        // All protocols succeed
        if icmp_success && (!any_tcp || any_tcp_success) && (!any_udp || any_udp_success) {
            let all_tcp_success = tcp_results.iter().all(|r| r.success);
            let all_udp_success = udp_results.iter().all(|r| r.success);

            if all_tcp_success && all_udp_success {
                return PathClassification::Open;
            }

            let open_ports: Vec<u16> = results.iter()
                .filter(|r| r.success)
                .filter_map(|r| r.protocol.port())
                .collect();

            let closed_ports: Vec<u16> = results.iter()
                .filter(|r| !r.success)
                .filter_map(|r| r.protocol.port())
                .collect();

            if !open_ports.is_empty() && !closed_ports.is_empty() {
                return PathClassification::SelectiveFirewall { open_ports, closed_ports };
            }
        }

        // No ICMP probed, but TCP/UDP work - classify based on available data
        if !has_icmp && (any_tcp_success || any_udp_success) {
            let all_tcp_success = tcp_results.is_empty() || tcp_results.iter().all(|r| r.success);
            let all_udp_success = udp_results.is_empty() || udp_results.iter().all(|r| r.success);

            if all_tcp_success && all_udp_success {
                // Can't determine ICMP status, but TCP/UDP are open
                return PathClassification::IcmpFiltered; // Assume ICMP filtered if not tested
            }
        }

        // ICMP blocked but TCP/UDP open
        if has_icmp && !icmp_success && (any_tcp_success || any_udp_success) {
            return PathClassification::IcmpFiltered;
        }

        // ICMP succeeds but TCP fails
        if icmp_success && any_tcp && !any_tcp_success {
            return PathClassification::TcpFiltered;
        }

        // All fail
        let all_fail = (!has_icmp || !icmp_success) && !any_tcp_success && !any_udp_success;
        if all_fail && (has_icmp || any_tcp || any_udp) {
            return PathClassification::Blocked;
        }

        // Check for NAT indicators
        let ttls: Vec<u8> = results.iter()
            .filter_map(|r| r.ttl)
            .collect();

        if ttls.len() >= 2 {
            let min_ttl = *ttls.iter().min().unwrap();
            let max_ttl = *ttls.iter().max().unwrap();

            if max_ttl - min_ttl > 5 {
                return PathClassification::NatDetected;
            }
        }

        PathClassification::Unknown
    }

    /// Calculate Protocol Differential Score
    pub fn differential_score(results: &[ProbeResult]) -> ProtocolDifferentialScore {
        ProtocolDifferentialScore::calculate(results)
    }

    /// Generate a human-readable fingerprint string
    pub fn fingerprint(results: &[ProbeResult]) -> String {
        let mut parts = Vec::new();

        // ICMP status
        let icmp = results.iter()
            .find(|r| matches!(r.protocol, Protocol::Icmp));
        if let Some(r) = icmp {
            parts.push(format!("ICMP:{}", if r.success { "open" } else { "filtered" }));
        }

        // TCP ports
        let tcp_open: Vec<_> = results.iter()
            .filter(|r| matches!(r.protocol, Protocol::Tcp(_)) && r.success)
            .filter_map(|r| r.protocol.port())
            .collect();
        let tcp_closed: Vec<_> = results.iter()
            .filter(|r| matches!(r.protocol, Protocol::Tcp(_)) && !r.success)
            .filter_map(|r| r.protocol.port())
            .collect();

        if !tcp_open.is_empty() {
            parts.push(format!("TCP-open:{tcp_open:?}"));
        }
        if !tcp_closed.is_empty() {
            parts.push(format!("TCP-closed:{tcp_closed:?}"));
        }

        // UDP ports
        let udp_open: Vec<_> = results.iter()
            .filter(|r| matches!(r.protocol, Protocol::Udp(_)) && r.success)
            .filter_map(|r| r.protocol.port())
            .collect();
        let udp_closed: Vec<_> = results.iter()
            .filter(|r| matches!(r.protocol, Protocol::Udp(_)) && !r.success)
            .filter_map(|r| r.protocol.port())
            .collect();

        if !udp_open.is_empty() {
            parts.push(format!("UDP-open:{udp_open:?}"));
        }
        if !udp_closed.is_empty() {
            parts.push(format!("UDP-closed:{udp_closed:?}"));
        }

        if parts.is_empty() {
            "Unknown".to_string()
        } else {
            parts.join(" | ")
        }
    }

    /// Generate a compact fingerprint hash for comparison
    pub fn fingerprint_hash(results: &[ProbeResult]) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();

        // Sort results by protocol for consistent hashing
        let mut sorted: Vec<_> = results.iter().collect();
        sorted.sort_by_key(|r| format!("{}", r.protocol));

        for result in sorted {
            result.protocol.to_string().hash(&mut hasher);
            result.success.hash(&mut hasher);
        }

        hasher.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TimingBreakdown;
    use std::net::IpAddr;
    use std::time::Duration;

    fn make_result(protocol: Protocol, success: bool) -> ProbeResult {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let timing = TimingBreakdown::new(None, Duration::from_millis(10), Duration::from_millis(20));

        if success {
            ProbeResult::success("test".to_string(), ip, protocol, timing)
        } else {
            ProbeResult::failure("test".to_string(), ip, protocol, "failed".to_string(), timing)
        }
    }

    #[test]
    fn test_classify_open() {
        let results = vec![
            make_result(Protocol::Icmp, true),
            make_result(Protocol::Tcp(80), true),
            make_result(Protocol::Tcp(443), true),
        ];

        assert_eq!(Classifier::classify(&results), PathClassification::Open);
    }

    #[test]
    fn test_classify_icmp_filtered() {
        let results = vec![
            make_result(Protocol::Icmp, false),
            make_result(Protocol::Tcp(443), true),
        ];

        assert_eq!(Classifier::classify(&results), PathClassification::IcmpFiltered);
    }

    #[test]
    fn test_classify_blocked() {
        let results = vec![
            make_result(Protocol::Icmp, false),
            make_result(Protocol::Tcp(80), false),
            make_result(Protocol::Tcp(443), false),
        ];

        assert_eq!(Classifier::classify(&results), PathClassification::Blocked);
    }

    #[test]
    fn test_fingerprint() {
        let results = vec![
            make_result(Protocol::Icmp, false),
            make_result(Protocol::Tcp(80), false),
            make_result(Protocol::Tcp(443), true),
        ];

        let fp = Classifier::fingerprint(&results);
        assert!(fp.contains("ICMP:filtered"));
        assert!(fp.contains("TCP-open:[443]"));
        assert!(fp.contains("TCP-closed:[80]"));
    }

    #[test]
    fn test_differential_score_consistent() {
        let results = vec![
            make_result(Protocol::Icmp, true),
            make_result(Protocol::Tcp(80), true),
            make_result(Protocol::Tcp(443), true),
            make_result(Protocol::Udp(53), true),
        ];

        let score = Classifier::differential_score(&results);
        assert!(score.consistency > 0.9);
        assert_eq!(score.interpret(), NetworkBehavior::Direct);
    }

    #[test]
    fn test_differential_score_icmp_filtered() {
        let results = vec![
            make_result(Protocol::Icmp, false),
            make_result(Protocol::Tcp(80), true),
            make_result(Protocol::Tcp(443), true),
            make_result(Protocol::Udp(53), true),
        ];

        let score = Classifier::differential_score(&results);
        assert!(score.icmp_tcp_diff > 0.5);
        assert_eq!(score.interpret(), NetworkBehavior::IcmpFiltering);
    }

    #[test]
    fn test_fingerprint_hash_consistency() {
        let results1 = vec![
            make_result(Protocol::Tcp(80), true),
            make_result(Protocol::Tcp(443), true),
        ];

        let results2 = vec![
            make_result(Protocol::Tcp(443), true),
            make_result(Protocol::Tcp(80), true),
        ];

        // Same results in different order should produce same hash
        assert_eq!(
            Classifier::fingerprint_hash(&results1),
            Classifier::fingerprint_hash(&results2)
        );
    }
}
