//! Protocol Divergence Localization
//!
//! Identifies WHERE in a network path different protocols start behaving differently.
//! Runs ICMP, TCP, and UDP traceroutes in parallel and compares results at each hop.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use std::mem::MaybeUninit;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::task::JoinSet;

use crate::dns;
use crate::error::Error;

/// Protocol used for probing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DivergenceProtocol {
    Icmp,
    Tcp,
    Udp,
}

impl std::fmt::Display for DivergenceProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Icmp => write!(f, "ICMP"),
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
        }
    }
}

/// Status of a protocol probe at a specific hop
#[derive(Debug, Clone, PartialEq)]
pub enum HopStatus {
    /// Received response from this hop
    Responded {
        addr: IpAddr,
        rtt: Duration,
    },
    /// Timeout - no response within time limit
    Timeout,
    /// Destination unreachable (various ICMP codes)
    Unreachable {
        code: u8,
    },
    /// Filtered - likely firewall blocking
    Filtered,
}

impl HopStatus {
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Responded { .. })
    }

    pub fn addr(&self) -> Option<IpAddr> {
        match self {
            Self::Responded { addr, .. } => Some(*addr),
            _ => None,
        }
    }

    pub fn rtt(&self) -> Option<Duration> {
        match self {
            Self::Responded { rtt, .. } => Some(*rtt),
            _ => None,
        }
    }
}

impl std::fmt::Display for HopStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Responded { addr, rtt } => {
                write!(f, "{} ({:.2}ms)", addr, rtt.as_secs_f64() * 1000.0)
            }
            Self::Timeout => write!(f, "*"),
            Self::Unreachable { code } => write!(f, "!H{code}"),
            Self::Filtered => write!(f, "!X"),
        }
    }
}

/// Result for a single protocol at a single hop
#[derive(Debug, Clone)]
pub struct ProtocolHopResult {
    pub protocol: DivergenceProtocol,
    pub ttl: u8,
    pub status: HopStatus,
}

/// Combined results for all protocols at a single hop
#[derive(Debug, Clone)]
pub struct DivergenceHop {
    pub ttl: u8,
    pub results: HashMap<DivergenceProtocol, HopStatus>,
    /// Agreement score: 1.0 = all protocols agree, 0.0 = complete disagreement
    pub agreement_score: f64,
    /// Whether this hop shows protocol divergence
    pub has_divergence: bool,
    /// Human-readable description of divergence (if any)
    pub divergence_description: Option<String>,
}

impl DivergenceHop {
    fn new(ttl: u8, results: HashMap<DivergenceProtocol, HopStatus>) -> Self {
        let (agreement_score, has_divergence, description) = Self::analyze_divergence(&results);

        Self {
            ttl,
            results,
            agreement_score,
            has_divergence,
            divergence_description: description,
        }
    }

    fn analyze_divergence(results: &HashMap<DivergenceProtocol, HopStatus>) -> (f64, bool, Option<String>) {
        if results.is_empty() {
            return (1.0, false, None);
        }

        let success_count = results.values().filter(|s| s.is_success()).count();
        let total = results.len();

        // Agreement score based on success/fail consistency
        let agreement = if total == 0 || success_count == total || success_count == 0 {
            1.0 // Edge case, all succeed, or all fail = agreement
        } else {
            success_count as f64 / total as f64 // Partial agreement
        };

        let has_divergence = agreement < 1.0;

        let description = if has_divergence {
            let successes: Vec<_> = results.iter()
                .filter(|(_, s)| s.is_success())
                .map(|(p, _)| p.to_string())
                .collect();
            let failures: Vec<_> = results.iter()
                .filter(|(_, s)| !s.is_success())
                .map(|(p, _)| p.to_string())
                .collect();

            Some(format!(
                "{} succeeded, {} failed",
                successes.join("/"),
                failures.join("/")
            ))
        } else {
            None
        };

        (agreement, has_divergence, description)
    }

    /// Get a symbol indicating hop status
    pub fn status_symbol(&self) -> &'static str {
        if self.has_divergence {
            "⚠"  // Divergence detected
        } else if self.results.values().all(|s| s.is_success()) {
            "✓"  // All succeeded
        } else if self.results.values().all(|s| !s.is_success()) {
            "✗"  // All failed
        } else {
            "?"  // Unknown
        }
    }
}

/// Complete divergence analysis result
#[derive(Debug)]
pub struct DivergenceResult {
    pub target: String,
    pub target_ip: IpAddr,
    pub protocols_used: Vec<DivergenceProtocol>,
    pub hops: Vec<DivergenceHop>,
    /// First hop where divergence occurs (1-indexed)
    pub first_divergence_hop: Option<u8>,
    /// Overall path divergence score (0.0 = no divergence, 1.0 = complete divergence)
    pub path_divergence_score: f64,
    /// Whether destination was reached by all protocols
    pub all_reached_destination: bool,
    /// Protocols that reached destination
    pub protocols_reached: Vec<DivergenceProtocol>,
    pub total_time: Duration,
}

impl DivergenceResult {
    /// Get a summary of the divergence analysis
    pub fn summary(&self) -> String {
        if let Some(hop) = self.first_divergence_hop {
            format!(
                "Protocol divergence detected at hop {}. Path score: {:.2}",
                hop, self.path_divergence_score
            )
        } else {
            "No protocol divergence detected - all protocols behave consistently".to_string()
        }
    }

    /// Get the hop where divergence starts
    pub fn divergence_point(&self) -> Option<&DivergenceHop> {
        self.first_divergence_hop
            .and_then(|h| self.hops.get((h - 1) as usize))
    }

    /// Check if a specific protocol reached the destination
    pub fn protocol_reached(&self, protocol: DivergenceProtocol) -> bool {
        self.protocols_reached.contains(&protocol)
    }
}

/// Options for divergence analysis
#[derive(Debug, Clone)]
pub struct DivergenceOptions {
    pub max_hops: u8,
    pub timeout_per_hop: Duration,
    pub protocols: Vec<DivergenceProtocol>,
    pub tcp_port: u16,
    pub udp_port: u16,
}

impl Default for DivergenceOptions {
    fn default() -> Self {
        Self {
            max_hops: 30,
            timeout_per_hop: Duration::from_secs(2),
            protocols: vec![
                DivergenceProtocol::Icmp,
                DivergenceProtocol::Tcp,
                DivergenceProtocol::Udp,
            ],
            tcp_port: 80,
            udp_port: 33434,
        }
    }
}

/// Run divergence analysis - trace route with multiple protocols and compare
pub async fn analyze_divergence(
    target: &str,
    options: &DivergenceOptions,
) -> crate::Result<DivergenceResult> {
    let start_time = Instant::now();

    // Resolve target
    let dns_result = dns::resolve_ipv4(target).await?;
    let target_ip = dns_result.ip;

    let target_ipv4 = match target_ip {
        IpAddr::V4(ipv4) => ipv4,
        IpAddr::V6(_) => return Err(Error::InvalidTarget("IPv6 not yet supported".to_string())),
    };

    let mut hops = Vec::new();
    let mut first_divergence_hop = None;
    let mut protocols_reached: HashMap<DivergenceProtocol, bool> = HashMap::new();

    for protocol in &options.protocols {
        protocols_reached.insert(*protocol, false);
    }

    for ttl in 1..=options.max_hops {
        // Probe all protocols at this hop in parallel
        let mut results: HashMap<DivergenceProtocol, HopStatus> = HashMap::new();
        let mut join_set = JoinSet::new();

        for &protocol in &options.protocols {
            let target_v4 = target_ipv4;
            let timeout = options.timeout_per_hop;
            let tcp_port = options.tcp_port;
            let udp_port = options.udp_port;

            join_set.spawn(async move {
                let status = probe_hop_protocol(target_v4, ttl, protocol, timeout, tcp_port, udp_port).await;
                (protocol, status)
            });
        }

        while let Some(result) = join_set.join_next().await {
            if let Ok((protocol, status)) = result {
                // Check if this protocol reached destination
                if let HopStatus::Responded { addr, .. } = &status {
                    if *addr == target_ip {
                        protocols_reached.insert(protocol, true);
                    }
                }
                results.insert(protocol, status);
            }
        }

        let hop = DivergenceHop::new(ttl, results);

        // Track first divergence
        if hop.has_divergence && first_divergence_hop.is_none() {
            first_divergence_hop = Some(ttl);
        }

        hops.push(hop);

        // Stop if all protocols reached destination
        if protocols_reached.values().all(|&v| v) {
            break;
        }
    }

    // Calculate path divergence score
    let divergent_hops = hops.iter().filter(|h| h.has_divergence).count();
    let path_divergence_score = if hops.is_empty() {
        0.0
    } else {
        divergent_hops as f64 / hops.len() as f64
    };

    let protocols_that_reached: Vec<_> = protocols_reached
        .iter()
        .filter(|(_, &reached)| reached)
        .map(|(&p, _)| p)
        .collect();

    Ok(DivergenceResult {
        target: target.to_string(),
        target_ip,
        protocols_used: options.protocols.clone(),
        hops,
        first_divergence_hop,
        path_divergence_score,
        all_reached_destination: protocols_reached.values().all(|&v| v),
        protocols_reached: protocols_that_reached,
        total_time: start_time.elapsed(),
    })
}

async fn probe_hop_protocol(
    target: Ipv4Addr,
    ttl: u8,
    protocol: DivergenceProtocol,
    timeout: Duration,
    tcp_port: u16,
    udp_port: u16,
) -> HopStatus {
    let result = tokio::task::spawn_blocking(move || {
        match protocol {
            DivergenceProtocol::Icmp => probe_hop_icmp(target, ttl, timeout),
            DivergenceProtocol::Tcp => probe_hop_tcp(target, ttl, timeout, tcp_port),
            DivergenceProtocol::Udp => probe_hop_udp(target, ttl, timeout, udp_port),
        }
    }).await;

    match result {
        Ok(status) => status,
        Err(_) => HopStatus::Timeout,
    }
}

fn probe_hop_icmp(target: Ipv4Addr, ttl: u8, timeout: Duration) -> HopStatus {
    let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
        Ok(s) => s,
        Err(_) => return HopStatus::Filtered,
    };

    if socket.set_ttl(ttl as u32).is_err() {
        return HopStatus::Filtered;
    }
    if socket.set_read_timeout(Some(timeout)).is_err() {
        return HopStatus::Timeout;
    }

    let packet = build_icmp_echo(ttl);
    let dest = SocketAddr::new(IpAddr::V4(target), 0);
    let start = Instant::now();

    if socket.send_to(&packet, &dest.into()).is_err() {
        return HopStatus::Filtered;
    }

    let mut recv_buf: [MaybeUninit<u8>; 1024] = unsafe { MaybeUninit::uninit().assume_init() };

    match socket.recv_from(&mut recv_buf) {
        Ok((len, from_addr)) => {
            let rtt = start.elapsed();
            let buf: &[u8] = unsafe {
                std::slice::from_raw_parts(recv_buf.as_ptr() as *const u8, len)
            };

            if len >= 28 {
                let ip_header_len = ((buf[0] & 0x0F) * 4) as usize;
                if len > ip_header_len {
                    let icmp_type = buf[ip_header_len];
                    let icmp_code = buf[ip_header_len + 1];

                    let from_ip = match from_addr.as_socket_ipv4() {
                        Some(addr) => IpAddr::V4(*addr.ip()),
                        None => return HopStatus::Timeout,
                    };

                    match icmp_type {
                        0 | 11 => HopStatus::Responded { addr: from_ip, rtt },
                        3 => HopStatus::Unreachable { code: icmp_code },
                        _ => HopStatus::Responded { addr: from_ip, rtt },
                    }
                } else {
                    HopStatus::Timeout
                }
            } else {
                HopStatus::Timeout
            }
        }
        Err(_) => HopStatus::Timeout,
    }
}

fn probe_hop_tcp(target: Ipv4Addr, ttl: u8, timeout: Duration, port: u16) -> HopStatus {
    // For TCP traceroute, we need to send a SYN and listen for ICMP TTL exceeded
    // This is simplified - uses raw socket to catch ICMP responses
    let icmp_socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
        Ok(s) => s,
        Err(_) => return HopStatus::Filtered,
    };

    if icmp_socket.set_read_timeout(Some(timeout)).is_err() {
        return HopStatus::Timeout;
    }

    // Create TCP socket
    let tcp_socket = match Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)) {
        Ok(s) => s,
        Err(_) => return HopStatus::Filtered,
    };

    if tcp_socket.set_ttl(ttl as u32).is_err() {
        return HopStatus::Filtered;
    }

    tcp_socket.set_nonblocking(true).ok();

    let dest = SocketAddr::new(IpAddr::V4(target), port);
    let start = Instant::now();

    // Initiate connection (will trigger TTL exceeded)
    let _ = tcp_socket.connect(&dest.into());

    // Wait for ICMP response
    let mut recv_buf: [MaybeUninit<u8>; 1024] = unsafe { MaybeUninit::uninit().assume_init() };

    match icmp_socket.recv_from(&mut recv_buf) {
        Ok((len, from_addr)) => {
            let rtt = start.elapsed();
            let buf: &[u8] = unsafe {
                std::slice::from_raw_parts(recv_buf.as_ptr() as *const u8, len)
            };

            if len >= 28 {
                let ip_header_len = ((buf[0] & 0x0F) * 4) as usize;
                if len > ip_header_len {
                    let icmp_type = buf[ip_header_len];
                    let icmp_code = buf[ip_header_len + 1];

                    let from_ip = match from_addr.as_socket_ipv4() {
                        Some(addr) => IpAddr::V4(*addr.ip()),
                        None => return HopStatus::Timeout,
                    };

                    match icmp_type {
                        11 => HopStatus::Responded { addr: from_ip, rtt }, // TTL exceeded
                        3 => HopStatus::Unreachable { code: icmp_code },
                        _ => HopStatus::Responded { addr: from_ip, rtt },
                    }
                } else {
                    HopStatus::Timeout
                }
            } else {
                HopStatus::Timeout
            }
        }
        Err(_) => HopStatus::Timeout,
    }
}

fn probe_hop_udp(target: Ipv4Addr, ttl: u8, timeout: Duration, port: u16) -> HopStatus {
    // Listen for ICMP responses
    let icmp_socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
        Ok(s) => s,
        Err(_) => return HopStatus::Filtered,
    };

    if icmp_socket.set_read_timeout(Some(timeout)).is_err() {
        return HopStatus::Timeout;
    }

    // Create UDP socket
    let udp_socket = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) {
        Ok(s) => s,
        Err(_) => return HopStatus::Filtered,
    };

    if udp_socket.set_ttl(ttl as u32).is_err() {
        return HopStatus::Filtered;
    }

    let dest = SocketAddr::new(IpAddr::V4(target), port);
    let start = Instant::now();

    // Send UDP packet
    let payload = b"multiprobe";
    if udp_socket.send_to(payload, &dest.into()).is_err() {
        return HopStatus::Filtered;
    }

    // Wait for ICMP response
    let mut recv_buf: [MaybeUninit<u8>; 1024] = unsafe { MaybeUninit::uninit().assume_init() };

    match icmp_socket.recv_from(&mut recv_buf) {
        Ok((len, from_addr)) => {
            let rtt = start.elapsed();
            let buf: &[u8] = unsafe {
                std::slice::from_raw_parts(recv_buf.as_ptr() as *const u8, len)
            };

            if len >= 28 {
                let ip_header_len = ((buf[0] & 0x0F) * 4) as usize;
                if len > ip_header_len {
                    let icmp_type = buf[ip_header_len];
                    let icmp_code = buf[ip_header_len + 1];

                    let from_ip = match from_addr.as_socket_ipv4() {
                        Some(addr) => IpAddr::V4(*addr.ip()),
                        None => return HopStatus::Timeout,
                    };

                    match icmp_type {
                        11 => HopStatus::Responded { addr: from_ip, rtt }, // TTL exceeded
                        3 => {
                            if icmp_code == 3 {
                                // Port unreachable - we reached destination
                                HopStatus::Responded { addr: from_ip, rtt }
                            } else {
                                HopStatus::Unreachable { code: icmp_code }
                            }
                        }
                        _ => HopStatus::Responded { addr: from_ip, rtt },
                    }
                } else {
                    HopStatus::Timeout
                }
            } else {
                HopStatus::Timeout
            }
        }
        Err(_) => HopStatus::Timeout,
    }
}

fn build_icmp_echo(sequence: u8) -> Vec<u8> {
    let mut packet = vec![0u8; 64];
    let identifier = std::process::id() as u16;

    packet[0] = 8; // Echo Request
    packet[1] = 0; // Code
    packet[4] = (identifier >> 8) as u8;
    packet[5] = identifier as u8;
    packet[6] = 0;
    packet[7] = sequence;

    let checksum = compute_icmp_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = checksum as u8;

    packet
}

fn compute_icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    while i < data.len() {
        let word = if i + 1 < data.len() {
            ((data[i] as u32) << 8) | (data[i + 1] as u32)
        } else {
            (data[i] as u32) << 8
        };
        sum = sum.wrapping_add(word);
        i += 2;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hop_status_display() {
        let responded = HopStatus::Responded {
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            rtt: Duration::from_millis(10),
        };
        assert!(responded.to_string().contains("192.168.1.1"));

        let timeout = HopStatus::Timeout;
        assert_eq!(timeout.to_string(), "*");

        let unreachable = HopStatus::Unreachable { code: 3 };
        assert!(unreachable.to_string().contains("!H3"));

        let filtered = HopStatus::Filtered;
        assert_eq!(filtered.to_string(), "!X");
    }

    #[test]
    fn test_hop_status_accessors() {
        let responded = HopStatus::Responded {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            rtt: Duration::from_millis(5),
        };
        assert!(responded.is_success());
        assert_eq!(responded.addr(), Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(responded.rtt(), Some(Duration::from_millis(5)));

        let timeout = HopStatus::Timeout;
        assert!(!timeout.is_success());
        assert_eq!(timeout.addr(), None);
        assert_eq!(timeout.rtt(), None);

        let filtered = HopStatus::Filtered;
        assert!(!filtered.is_success());
    }

    #[test]
    fn test_divergence_hop_analysis() {
        let mut results = HashMap::new();
        results.insert(DivergenceProtocol::Icmp, HopStatus::Responded {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            rtt: Duration::from_millis(5),
        });
        results.insert(DivergenceProtocol::Tcp, HopStatus::Timeout);
        results.insert(DivergenceProtocol::Udp, HopStatus::Timeout);

        let hop = DivergenceHop::new(5, results);

        assert!(hop.has_divergence);
        assert!(hop.divergence_description.is_some());
        assert!(hop.divergence_description.as_ref().unwrap().contains("ICMP"));
        assert_eq!(hop.status_symbol(), "⚠");
    }

    #[test]
    fn test_no_divergence() {
        let mut results = HashMap::new();
        results.insert(DivergenceProtocol::Icmp, HopStatus::Responded {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            rtt: Duration::from_millis(5),
        });
        results.insert(DivergenceProtocol::Tcp, HopStatus::Responded {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            rtt: Duration::from_millis(6),
        });

        let hop = DivergenceHop::new(1, results);

        assert!(!hop.has_divergence);
        assert_eq!(hop.agreement_score, 1.0);
        assert_eq!(hop.status_symbol(), "✓");
    }

    #[test]
    fn test_all_timeout() {
        let mut results = HashMap::new();
        results.insert(DivergenceProtocol::Icmp, HopStatus::Timeout);
        results.insert(DivergenceProtocol::Tcp, HopStatus::Timeout);
        results.insert(DivergenceProtocol::Udp, HopStatus::Timeout);

        let hop = DivergenceHop::new(3, results);

        assert!(!hop.has_divergence);
        assert_eq!(hop.agreement_score, 1.0);
        assert_eq!(hop.status_symbol(), "✗");
    }

    #[test]
    fn test_partial_divergence_two_protocols() {
        let mut results = HashMap::new();
        results.insert(DivergenceProtocol::Icmp, HopStatus::Responded {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            rtt: Duration::from_millis(5),
        });
        results.insert(DivergenceProtocol::Tcp, HopStatus::Responded {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            rtt: Duration::from_millis(6),
        });
        results.insert(DivergenceProtocol::Udp, HopStatus::Timeout);

        let hop = DivergenceHop::new(2, results);

        assert!(hop.has_divergence);
        // 2/3 succeeded = 0.666...
        assert!(hop.agreement_score > 0.6 && hop.agreement_score < 0.7);
    }

    #[test]
    fn test_empty_results() {
        let results = HashMap::new();
        let hop = DivergenceHop::new(1, results);

        assert!(!hop.has_divergence);
        assert_eq!(hop.agreement_score, 1.0);
    }

    #[test]
    fn test_single_protocol() {
        let mut results = HashMap::new();
        results.insert(DivergenceProtocol::Icmp, HopStatus::Responded {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            rtt: Duration::from_millis(5),
        });

        let hop = DivergenceHop::new(1, results);

        assert!(!hop.has_divergence);
        assert_eq!(hop.agreement_score, 1.0);
    }

    #[test]
    fn test_unreachable_status() {
        let mut results = HashMap::new();
        results.insert(DivergenceProtocol::Icmp, HopStatus::Responded {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            rtt: Duration::from_millis(5),
        });
        results.insert(DivergenceProtocol::Tcp, HopStatus::Unreachable { code: 1 });
        results.insert(DivergenceProtocol::Udp, HopStatus::Unreachable { code: 3 });

        let hop = DivergenceHop::new(4, results);

        assert!(hop.has_divergence);
    }

    #[test]
    fn test_default_options() {
        let opts = DivergenceOptions::default();
        assert_eq!(opts.max_hops, 30);
        assert_eq!(opts.protocols.len(), 3);
        assert_eq!(opts.timeout_per_hop, Duration::from_secs(2));
        assert_eq!(opts.tcp_port, 80);
        assert_eq!(opts.udp_port, 33434);
    }

    #[test]
    fn test_protocol_display() {
        assert_eq!(format!("{}", DivergenceProtocol::Icmp), "ICMP");
        assert_eq!(format!("{}", DivergenceProtocol::Tcp), "TCP");
        assert_eq!(format!("{}", DivergenceProtocol::Udp), "UDP");
    }

    #[test]
    fn test_divergence_result_summary_no_divergence() {
        let result = DivergenceResult {
            target: "example.com".to_string(),
            target_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            protocols_used: vec![DivergenceProtocol::Icmp, DivergenceProtocol::Tcp],
            hops: vec![],
            first_divergence_hop: None,
            path_divergence_score: 0.0,
            all_reached_destination: true,
            protocols_reached: vec![DivergenceProtocol::Icmp, DivergenceProtocol::Tcp],
            total_time: Duration::from_secs(1),
        };

        assert!(result.summary().contains("No protocol divergence"));
        assert!(result.divergence_point().is_none());
        assert!(result.protocol_reached(DivergenceProtocol::Icmp));
        assert!(result.protocol_reached(DivergenceProtocol::Tcp));
    }

    #[test]
    fn test_divergence_result_with_divergence() {
        let mut hop_results = HashMap::new();
        hop_results.insert(DivergenceProtocol::Icmp, HopStatus::Responded {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            rtt: Duration::from_millis(5),
        });
        hop_results.insert(DivergenceProtocol::Tcp, HopStatus::Timeout);

        let hop = DivergenceHop::new(3, hop_results);

        let result = DivergenceResult {
            target: "example.com".to_string(),
            target_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            protocols_used: vec![DivergenceProtocol::Icmp, DivergenceProtocol::Tcp],
            hops: vec![
                DivergenceHop::new(1, HashMap::new()),
                DivergenceHop::new(2, HashMap::new()),
                hop,
            ],
            first_divergence_hop: Some(3),
            path_divergence_score: 0.33,
            all_reached_destination: false,
            protocols_reached: vec![DivergenceProtocol::Icmp],
            total_time: Duration::from_secs(2),
        };

        assert!(result.summary().contains("hop 3"));
        assert!(result.divergence_point().is_some());
        assert_eq!(result.divergence_point().unwrap().ttl, 3);
        assert!(result.protocol_reached(DivergenceProtocol::Icmp));
        assert!(!result.protocol_reached(DivergenceProtocol::Tcp));
    }
}
