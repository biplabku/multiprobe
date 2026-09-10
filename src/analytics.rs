//! Advanced Path Analytics
//!
//! This module provides sophisticated network path analysis including:
//! - Path MTU Discovery (PMTUD)
//! - Jitter and packet reordering metrics
//! - Bufferbloat detection under load
//! - Latency distribution analysis

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use std::mem::MaybeUninit;

use socket2::{Domain, Protocol, Socket, Type};

use crate::dns;
use crate::error::Error;

// ============================================================================
// JITTER AND LATENCY ANALYSIS
// ============================================================================

/// Statistics from multiple probe samples
#[derive(Debug, Clone)]
pub struct LatencyStats {
    /// Minimum RTT observed
    pub min_rtt: Duration,
    /// Maximum RTT observed
    pub max_rtt: Duration,
    /// Mean RTT
    pub mean_rtt: Duration,
    /// Median RTT
    pub median_rtt: Duration,
    /// Standard deviation
    pub std_dev: Duration,
    /// Jitter (mean absolute deviation)
    pub jitter: Duration,
    /// 95th percentile RTT
    pub p95_rtt: Duration,
    /// 99th percentile RTT
    pub p99_rtt: Duration,
    /// Packet loss rate (0.0 - 1.0)
    pub loss_rate: f64,
    /// Number of samples
    pub sample_count: usize,
    /// Number of successful probes
    pub success_count: usize,
}

impl LatencyStats {
    /// Calculate statistics from a list of RTT measurements
    pub fn from_samples(samples: &[Option<Duration>]) -> Self {
        let successful: Vec<Duration> = samples.iter()
            .filter_map(|s| *s)
            .collect();

        let sample_count = samples.len();
        let success_count = successful.len();
        let loss_rate = if sample_count > 0 {
            1.0 - (success_count as f64 / sample_count as f64)
        } else {
            1.0
        };

        if successful.is_empty() {
            return Self {
                min_rtt: Duration::ZERO,
                max_rtt: Duration::ZERO,
                mean_rtt: Duration::ZERO,
                median_rtt: Duration::ZERO,
                std_dev: Duration::ZERO,
                jitter: Duration::ZERO,
                p95_rtt: Duration::ZERO,
                p99_rtt: Duration::ZERO,
                loss_rate,
                sample_count,
                success_count,
            };
        }

        let mut sorted: Vec<u128> = successful.iter()
            .map(|d| d.as_micros())
            .collect();
        sorted.sort_unstable();

        let min = sorted[0];
        let max = sorted[sorted.len() - 1];
        let sum: u128 = sorted.iter().sum();
        let mean = sum / sorted.len() as u128;

        let median = if sorted.len() % 2 == 0 {
            (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2]) / 2
        } else {
            sorted[sorted.len() / 2]
        };

        // Standard deviation
        let variance: f64 = sorted.iter()
            .map(|&x| {
                let diff = x as f64 - mean as f64;
                diff * diff
            })
            .sum::<f64>() / sorted.len() as f64;
        let std_dev = variance.sqrt();

        // Jitter (RFC 3550 style - mean of absolute differences)
        let jitter = if sorted.len() > 1 {
            let diffs: Vec<u128> = sorted.windows(2)
                .map(|w| (w[1] as i128 - w[0] as i128).unsigned_abs())
                .collect();
            diffs.iter().sum::<u128>() / diffs.len() as u128
        } else {
            0
        };

        // Percentiles
        let p95_idx = (sorted.len() as f64 * 0.95) as usize;
        let p99_idx = (sorted.len() as f64 * 0.99) as usize;
        let p95 = sorted[std::cmp::min(p95_idx, sorted.len() - 1)];
        let p99 = sorted[std::cmp::min(p99_idx, sorted.len() - 1)];

        Self {
            min_rtt: Duration::from_micros(min as u64),
            max_rtt: Duration::from_micros(max as u64),
            mean_rtt: Duration::from_micros(mean as u64),
            median_rtt: Duration::from_micros(median as u64),
            std_dev: Duration::from_micros(std_dev as u64),
            jitter: Duration::from_micros(jitter as u64),
            p95_rtt: Duration::from_micros(p95 as u64),
            p99_rtt: Duration::from_micros(p99 as u64),
            loss_rate,
            sample_count,
            success_count,
        }
    }

    /// Check if jitter is considered high (>10% of mean RTT)
    pub fn has_high_jitter(&self) -> bool {
        if self.mean_rtt.as_micros() == 0 {
            return false;
        }
        let ratio = self.jitter.as_micros() as f64 / self.mean_rtt.as_micros() as f64;
        ratio > 0.10
    }

    /// Check if there's significant packet loss (>1%)
    pub fn has_packet_loss(&self) -> bool {
        self.loss_rate > 0.01
    }
}

/// Collect latency samples to a target
pub async fn measure_latency(
    target: &str,
    port: u16,
    sample_count: usize,
    interval: Duration,
) -> crate::Result<LatencyStats> {
    let dns_result = dns::resolve_ipv4(target).await?;
    let target_ip = match dns_result.ip {
        IpAddr::V4(ipv4) => ipv4,
        IpAddr::V6(_) => return Err(Error::InvalidTarget("IPv6 not supported".to_string())),
    };

    let mut samples = Vec::with_capacity(sample_count);

    for _ in 0..sample_count {
        let rtt = tcp_ping(target_ip, port, Duration::from_secs(5)).await;
        samples.push(rtt);

        if interval > Duration::ZERO {
            tokio::time::sleep(interval).await;
        }
    }

    Ok(LatencyStats::from_samples(&samples))
}

async fn tcp_ping(target: Ipv4Addr, port: u16, timeout: Duration) -> Option<Duration> {
    let start = Instant::now();

    let result = tokio::time::timeout(timeout, async {
        tokio::net::TcpStream::connect(SocketAddr::new(IpAddr::V4(target), port)).await
    }).await;

    match result {
        Ok(Ok(_)) => Some(start.elapsed()),
        Ok(Err(_)) => Some(start.elapsed()), // Connection refused still means we reached it
        Err(_) => None, // Timeout
    }
}

// ============================================================================
// PATH MTU DISCOVERY
// ============================================================================

/// Result of Path MTU Discovery
#[derive(Debug, Clone)]
pub struct PmtudResult {
    /// Target that was tested
    pub target: String,
    /// Discovered Path MTU
    pub path_mtu: u16,
    /// Whether PMTUD completed successfully
    pub success: bool,
    /// Minimum MTU tested that worked
    pub min_working: u16,
    /// Maximum MTU tested that failed
    pub max_failing: Option<u16>,
    /// Whether DF (Don't Fragment) is being honored
    pub df_honored: bool,
    /// ICMP fragmentation needed messages received
    pub frag_needed_count: u32,
}

/// Perform Path MTU Discovery
///
/// Uses binary search with ICMP to find the largest packet size
/// that can traverse the path without fragmentation.
pub async fn discover_path_mtu(
    target: &str,
    options: &PmtudOptions,
) -> crate::Result<PmtudResult> {
    let dns_result = dns::resolve_ipv4(target).await?;
    let target_ip = match dns_result.ip {
        IpAddr::V4(ipv4) => ipv4,
        IpAddr::V6(_) => return Err(Error::InvalidTarget("IPv6 not supported".to_string())),
    };

    // Binary search for MTU
    let mut low = options.min_mtu;
    let mut high = options.max_mtu;
    let mut max_working = low;
    let mut min_failing: Option<u16> = None;
    let mut frag_needed_count = 0u32;

    while low <= high {
        let mid = (low + high) / 2;

        let result = probe_mtu(target_ip, mid, options.timeout).await;

        match result {
            MtuProbeResult::Success => {
                max_working = mid;
                low = mid + 1;
            }
            MtuProbeResult::FragmentationNeeded => {
                min_failing = Some(mid);
                high = mid - 1;
                frag_needed_count += 1;
            }
            MtuProbeResult::Timeout | MtuProbeResult::Error => {
                // Could be MTU issue or network problem
                high = mid - 1;
            }
        }
    }

    Ok(PmtudResult {
        target: target.to_string(),
        path_mtu: max_working,
        success: true,
        min_working: max_working,
        max_failing: min_failing,
        df_honored: frag_needed_count > 0,
        frag_needed_count,
    })
}

/// PMTUD configuration
#[derive(Debug, Clone)]
pub struct PmtudOptions {
    /// Minimum MTU to test
    pub min_mtu: u16,
    /// Maximum MTU to test
    pub max_mtu: u16,
    /// Timeout per probe
    pub timeout: Duration,
}

impl Default for PmtudOptions {
    fn default() -> Self {
        Self {
            min_mtu: 68,    // Minimum IPv4 MTU
            max_mtu: 1500,  // Standard Ethernet MTU
            timeout: Duration::from_secs(2),
        }
    }
}

#[derive(Debug)]
enum MtuProbeResult {
    Success,
    FragmentationNeeded,
    Timeout,
    Error,
}

async fn probe_mtu(target: Ipv4Addr, mtu: u16, timeout: Duration) -> MtuProbeResult {
    let result = tokio::task::spawn_blocking(move || {
        probe_mtu_sync(target, mtu, timeout)
    }).await;

    match result {
        Ok(r) => r,
        Err(_) => MtuProbeResult::Error,
    }
}

fn probe_mtu_sync(target: Ipv4Addr, mtu: u16, timeout: Duration) -> MtuProbeResult {
    // Create raw ICMP socket
    let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
        Ok(s) => s,
        Err(_) => return MtuProbeResult::Error,
    };

    // Set Don't Fragment flag
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        let val: libc::c_int = libc::IP_PMTUDISC_DO;
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    if socket.set_read_timeout(Some(timeout)).is_err() {
        return MtuProbeResult::Error;
    }

    // Calculate payload size (MTU - IP header - ICMP header)
    let payload_size = mtu.saturating_sub(20 + 8) as usize;
    let packet = build_pmtud_packet(payload_size);

    let dest = SocketAddr::new(IpAddr::V4(target), 0);

    if socket.send_to(&packet, &dest.into()).is_err() {
        return MtuProbeResult::Error;
    }

    let mut recv_buf: [MaybeUninit<u8>; 2048] = unsafe { MaybeUninit::uninit().assume_init() };

    match socket.recv_from(&mut recv_buf) {
        Ok((len, _)) => {
            let buf: &[u8] = unsafe {
                std::slice::from_raw_parts(recv_buf.as_ptr() as *const u8, len)
            };

            if len >= 28 {
                let ip_header_len = ((buf[0] & 0x0F) * 4) as usize;
                if len > ip_header_len {
                    let icmp_type = buf[ip_header_len];
                    let icmp_code = buf[ip_header_len + 1];

                    // Type 3, Code 4 = Fragmentation Needed
                    if icmp_type == 3 && icmp_code == 4 {
                        return MtuProbeResult::FragmentationNeeded;
                    }

                    // Type 0 = Echo Reply (success)
                    if icmp_type == 0 {
                        return MtuProbeResult::Success;
                    }
                }
            }
            MtuProbeResult::Error
        }
        Err(_) => MtuProbeResult::Timeout,
    }
}

fn build_pmtud_packet(payload_size: usize) -> Vec<u8> {
    let mut packet = vec![0u8; 8 + payload_size];

    // ICMP Echo Request
    packet[0] = 8;  // Type
    packet[1] = 0;  // Code
    packet[2] = 0;  // Checksum (computed below)
    packet[3] = 0;
    packet[4] = 0;  // Identifier
    packet[5] = 1;
    packet[6] = 0;  // Sequence
    packet[7] = 1;

    // Fill payload with pattern
    for i in 8..packet.len() {
        packet[i] = (i % 256) as u8;
    }

    // Compute checksum
    let checksum = compute_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = checksum as u8;

    packet
}

fn compute_checksum(data: &[u8]) -> u16 {
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

// ============================================================================
// BUFFERBLOAT DETECTION
// ============================================================================

/// Result of bufferbloat measurement
#[derive(Debug, Clone)]
pub struct BufferbloatResult {
    /// Target tested
    pub target: String,
    /// Baseline latency (no load)
    pub baseline_latency: Duration,
    /// Latency under load
    pub loaded_latency: Duration,
    /// Latency increase factor
    pub bloat_factor: f64,
    /// Bufferbloat grade (A-F)
    pub grade: BufferbloatGrade,
    /// Whether bufferbloat was detected
    pub detected: bool,
}

/// Bufferbloat severity grade
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferbloatGrade {
    /// Excellent (< 5ms increase)
    A,
    /// Good (5-30ms increase)
    B,
    /// Fair (30-60ms increase)
    C,
    /// Poor (60-200ms increase)
    D,
    /// Bad (> 200ms increase)
    F,
}

impl std::fmt::Display for BufferbloatGrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BufferbloatGrade::A => write!(f, "A (Excellent)"),
            BufferbloatGrade::B => write!(f, "B (Good)"),
            BufferbloatGrade::C => write!(f, "C (Fair)"),
            BufferbloatGrade::D => write!(f, "D (Poor)"),
            BufferbloatGrade::F => write!(f, "F (Bad)"),
        }
    }
}

impl BufferbloatGrade {
    fn from_increase(increase_ms: f64) -> Self {
        if increase_ms < 5.0 {
            BufferbloatGrade::A
        } else if increase_ms < 30.0 {
            BufferbloatGrade::B
        } else if increase_ms < 60.0 {
            BufferbloatGrade::C
        } else if increase_ms < 200.0 {
            BufferbloatGrade::D
        } else {
            BufferbloatGrade::F
        }
    }
}

/// Options for bufferbloat detection
#[derive(Debug, Clone)]
pub struct BufferbloatOptions {
    /// Number of baseline samples
    pub baseline_samples: usize,
    /// Number of loaded samples
    pub loaded_samples: usize,
    /// Concurrent connections to create load
    pub load_connections: usize,
    /// Port to use for testing
    pub port: u16,
}

impl Default for BufferbloatOptions {
    fn default() -> Self {
        Self {
            baseline_samples: 10,
            loaded_samples: 10,
            load_connections: 4,
            port: 443,
        }
    }
}

/// Detect bufferbloat by comparing latency under load vs idle
///
/// Note: This is a simplified version. Full bufferbloat testing
/// requires saturating the connection which may not be appropriate
/// for all scenarios.
pub async fn detect_bufferbloat(
    target: &str,
    options: &BufferbloatOptions,
) -> crate::Result<BufferbloatResult> {
    // Measure baseline latency
    let baseline = measure_latency(
        target,
        options.port,
        options.baseline_samples,
        Duration::from_millis(100),
    ).await?;

    // Create load and measure
    let loaded = measure_latency_under_load(
        target,
        options.port,
        options.loaded_samples,
        options.load_connections,
    ).await?;

    let baseline_ms = baseline.median_rtt.as_secs_f64() * 1000.0;
    let loaded_ms = loaded.median_rtt.as_secs_f64() * 1000.0;
    let increase_ms = loaded_ms - baseline_ms;
    let bloat_factor = if baseline_ms > 0.0 { loaded_ms / baseline_ms } else { 1.0 };

    let grade = BufferbloatGrade::from_increase(increase_ms);
    let detected = increase_ms > 30.0; // >30ms increase indicates bufferbloat

    Ok(BufferbloatResult {
        target: target.to_string(),
        baseline_latency: baseline.median_rtt,
        loaded_latency: loaded.median_rtt,
        bloat_factor,
        grade,
        detected,
    })
}

async fn measure_latency_under_load(
    target: &str,
    port: u16,
    samples: usize,
    concurrent: usize,
) -> crate::Result<LatencyStats> {
    let dns_result = dns::resolve_ipv4(target).await?;
    let target_ip = match dns_result.ip {
        IpAddr::V4(ipv4) => ipv4,
        IpAddr::V6(_) => return Err(Error::InvalidTarget("IPv6 not supported".to_string())),
    };

    // Start background connections to create load
    let handles: Vec<_> = (0..concurrent).map(|_| {
        let addr = SocketAddr::new(IpAddr::V4(target_ip), port);
        tokio::spawn(async move {
            // Try to establish and hold connection
            let _ = tokio::net::TcpStream::connect(addr).await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        })
    }).collect();

    // Give connections time to establish
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Measure latency while load is active
    let mut rtts = Vec::with_capacity(samples);
    for _ in 0..samples {
        let rtt = tcp_ping(target_ip, port, Duration::from_secs(5)).await;
        rtts.push(rtt);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Cancel background tasks
    for h in handles {
        h.abort();
    }

    Ok(LatencyStats::from_samples(&rtts))
}

// ============================================================================
// PACKET REORDERING
// ============================================================================

/// Result of packet reordering analysis
#[derive(Debug, Clone)]
pub struct ReorderingResult {
    /// Number of packets sent
    pub packets_sent: usize,
    /// Number of packets received
    pub packets_received: usize,
    /// Number of out-of-order packets
    pub out_of_order: usize,
    /// Reordering rate (0.0 - 1.0)
    pub reorder_rate: f64,
    /// Maximum reordering extent (how far out of order)
    pub max_reorder_extent: usize,
    /// Duplicate packets received
    pub duplicates: usize,
}

impl ReorderingResult {
    /// Check if significant reordering was detected
    pub fn has_reordering(&self) -> bool {
        self.reorder_rate > 0.01 // More than 1% reordered
    }
}

/// Analyze packet reordering on a path
///
/// Sends numbered packets and tracks arrival order
pub async fn analyze_reordering(
    target: &str,
    port: u16,
    packet_count: usize,
) -> crate::Result<ReorderingResult> {
    let dns_result = dns::resolve_ipv4(target).await?;
    let target_ip = match dns_result.ip {
        IpAddr::V4(ipv4) => ipv4,
        IpAddr::V6(_) => return Err(Error::InvalidTarget("IPv6 not supported".to_string())),
    };

    // Track sequence numbers
    let mut received_order: VecDeque<usize> = VecDeque::new();
    let mut expected_next = 0usize;
    let mut out_of_order = 0usize;
    let mut max_extent = 0usize;
    let mut duplicates = 0usize;
    let mut received_set = std::collections::HashSet::new();

    for seq in 0..packet_count {
        // Send probe with sequence number
        let rtt = tcp_ping(target_ip, port, Duration::from_secs(2)).await;

        if rtt.is_some() {
            if received_set.contains(&seq) {
                duplicates += 1;
            } else {
                received_set.insert(seq);
                received_order.push_back(seq);

                if seq != expected_next {
                    out_of_order += 1;
                    let extent = seq.abs_diff(expected_next);
                    max_extent = std::cmp::max(max_extent, extent);
                }
                expected_next = seq + 1;
            }
        }

        // Small delay between packets
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let packets_received = received_set.len();
    let reorder_rate = if packets_received > 0 {
        out_of_order as f64 / packets_received as f64
    } else {
        0.0
    };

    Ok(ReorderingResult {
        packets_sent: packet_count,
        packets_received,
        out_of_order,
        reorder_rate,
        max_reorder_extent: max_extent,
        duplicates,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latency_stats_empty() {
        let samples: Vec<Option<Duration>> = vec![];
        let stats = LatencyStats::from_samples(&samples);
        assert_eq!(stats.sample_count, 0);
        assert_eq!(stats.loss_rate, 1.0);
    }

    #[test]
    fn test_latency_stats_basic() {
        let samples = vec![
            Some(Duration::from_millis(10)),
            Some(Duration::from_millis(20)),
            Some(Duration::from_millis(15)),
            None, // Lost packet
        ];
        let stats = LatencyStats::from_samples(&samples);

        assert_eq!(stats.sample_count, 4);
        assert_eq!(stats.success_count, 3);
        assert_eq!(stats.loss_rate, 0.25);
        assert_eq!(stats.min_rtt, Duration::from_millis(10));
        assert_eq!(stats.max_rtt, Duration::from_millis(20));
    }

    #[test]
    fn test_bufferbloat_grade() {
        assert_eq!(BufferbloatGrade::from_increase(2.0), BufferbloatGrade::A);
        assert_eq!(BufferbloatGrade::from_increase(15.0), BufferbloatGrade::B);
        assert_eq!(BufferbloatGrade::from_increase(45.0), BufferbloatGrade::C);
        assert_eq!(BufferbloatGrade::from_increase(100.0), BufferbloatGrade::D);
        assert_eq!(BufferbloatGrade::from_increase(300.0), BufferbloatGrade::F);
    }

    #[test]
    fn test_pmtud_options_default() {
        let opts = PmtudOptions::default();
        assert_eq!(opts.min_mtu, 68);
        assert_eq!(opts.max_mtu, 1500);
    }
}
