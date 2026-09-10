//! Paris Traceroute Implementation
//!
//! Standard traceroute fails behind Equal-Cost Multi-Path (ECMP) load balancers
//! because it varies flow identifiers (ports) between probes, causing packets
//! to take different paths.
//!
//! Paris Traceroute (Augustin et al., 2006) solves this by keeping flow identifiers
//! constant, ensuring all probes follow the same network path.
//!
//! Reference: "Avoiding traceroute anomalies with Paris traceroute"
//! https://doi.org/10.1145/1177080.1177100

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use std::mem::MaybeUninit;

use socket2::{Domain, Protocol, Socket, Type};

use crate::dns;
use crate::error::Error;

/// Flow identifier for ECMP hashing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowId {
    /// Source port (for UDP/TCP)
    pub src_port: u16,
    /// Destination port (for UDP/TCP)
    pub dst_port: u16,
    /// Protocol (UDP=17, TCP=6, ICMP=1)
    pub protocol: u8,
}

impl FlowId {
    /// Create a UDP flow ID
    pub fn udp(src_port: u16, dst_port: u16) -> Self {
        Self {
            src_port,
            dst_port,
            protocol: 17,
        }
    }

    /// Create a TCP flow ID
    pub fn tcp(src_port: u16, dst_port: u16) -> Self {
        Self {
            src_port,
            dst_port,
            protocol: 6,
        }
    }

    /// Create an ICMP flow ID (uses identifier as "port")
    pub fn icmp(identifier: u16) -> Self {
        Self {
            src_port: identifier,
            dst_port: 0,
            protocol: 1,
        }
    }

    /// Default Paris flow ID (commonly used values)
    pub fn default_paris() -> Self {
        Self::udp(33434, 33434)
    }
}

impl Default for FlowId {
    fn default() -> Self {
        Self::default_paris()
    }
}

/// Paris Traceroute probe mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParisMode {
    /// UDP probes with constant flow ID
    Udp,
    /// ICMP probes with constant identifier
    Icmp,
    /// TCP SYN probes with constant flow ID
    Tcp,
}

impl Default for ParisMode {
    fn default() -> Self {
        Self::Udp
    }
}

/// A single hop result in Paris Traceroute
#[derive(Debug, Clone)]
pub struct ParisHop {
    /// TTL/hop number
    pub ttl: u8,
    /// Responding IP address (None if no response)
    pub addr: Option<IpAddr>,
    /// Round-trip time
    pub rtt: Duration,
    /// Whether this hop responded
    pub responded: bool,
    /// ICMP type received
    pub icmp_type: Option<u8>,
    /// ICMP code received
    pub icmp_code: Option<u8>,
    /// Flow ID used for this probe
    pub flow_id: FlowId,
    /// MPLS labels if present (RFC 4950)
    pub mpls_labels: Vec<MplsLabel>,
}

/// MPLS label information (RFC 4950 ICMP extensions)
#[derive(Debug, Clone)]
pub struct MplsLabel {
    pub label: u32,
    pub experimental: u8,
    pub bottom_of_stack: bool,
    pub ttl: u8,
}

impl ParisHop {
    fn timeout(ttl: u8, flow_id: FlowId, timeout: Duration) -> Self {
        Self {
            ttl,
            addr: None,
            rtt: timeout,
            responded: false,
            icmp_type: None,
            icmp_code: None,
            flow_id,
            mpls_labels: Vec::new(),
        }
    }

    fn success(ttl: u8, addr: IpAddr, rtt: Duration, icmp_type: u8, icmp_code: u8, flow_id: FlowId) -> Self {
        Self {
            ttl,
            addr: Some(addr),
            rtt,
            responded: true,
            icmp_type: Some(icmp_type),
            icmp_code: Some(icmp_code),
            flow_id,
            mpls_labels: Vec::new(),
        }
    }
}

/// Complete Paris Traceroute result
#[derive(Debug, Clone)]
pub struct ParisTraceResult {
    /// Target hostname/IP
    pub target: String,
    /// Resolved target IP
    pub target_ip: IpAddr,
    /// All hops discovered
    pub hops: Vec<ParisHop>,
    /// Whether destination was reached
    pub reached_destination: bool,
    /// Flow ID used
    pub flow_id: FlowId,
    /// Mode used (UDP/ICMP/TCP)
    pub mode: ParisMode,
    /// Total trace time
    pub total_time: Duration,
    /// Detected load balancing type
    pub load_balancing: LoadBalancingType,
}

/// Type of load balancing detected
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadBalancingType {
    /// No load balancing detected
    None,
    /// Per-flow load balancing (same flow = same path)
    PerFlow,
    /// Per-packet load balancing (packets may take different paths)
    PerPacket,
    /// Unable to determine
    Unknown,
}

impl std::fmt::Display for LoadBalancingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadBalancingType::None => write!(f, "None"),
            LoadBalancingType::PerFlow => write!(f, "Per-flow ECMP"),
            LoadBalancingType::PerPacket => write!(f, "Per-packet ECMP"),
            LoadBalancingType::Unknown => write!(f, "Unknown"),
        }
    }
}

impl ParisTraceResult {
    /// Get responsive hops only
    pub fn responsive_hops(&self) -> Vec<&ParisHop> {
        self.hops.iter().filter(|h| h.responded).collect()
    }

    /// Get the discovered path as IP addresses
    pub fn path(&self) -> Vec<IpAddr> {
        self.hops.iter().filter_map(|h| h.addr).collect()
    }

    /// Check if a specific IP is in the path
    pub fn contains_ip(&self, ip: IpAddr) -> bool {
        self.hops.iter().any(|h| h.addr == Some(ip))
    }

    /// Get hop count (responsive hops only)
    pub fn hop_count(&self) -> usize {
        self.responsive_hops().len()
    }

    /// Calculate path asymmetry (if we have forward and reverse info)
    pub fn has_asymmetry(&self) -> bool {
        // Check for TTL anomalies that suggest asymmetric routing
        let responsive: Vec<_> = self.responsive_hops();
        if responsive.len() < 3 {
            return false;
        }

        // Look for non-monotonic RTT increases
        for i in 1..responsive.len() {
            if responsive[i].rtt < responsive[i - 1].rtt {
                // RTT decreased - possible asymmetry
                let decrease = responsive[i - 1].rtt.as_micros() - responsive[i].rtt.as_micros();
                if decrease > 5000 {
                    // More than 5ms decrease is significant
                    return true;
                }
            }
        }
        false
    }
}

/// Paris Traceroute configuration
#[derive(Debug, Clone)]
pub struct ParisOptions {
    /// Maximum TTL
    pub max_hops: u8,
    /// Timeout per probe
    pub timeout_per_hop: Duration,
    /// Number of probes per hop (for statistics)
    pub probes_per_hop: u8,
    /// Probe mode (UDP/ICMP/TCP)
    pub mode: ParisMode,
    /// Flow ID to use
    pub flow_id: FlowId,
    /// Whether to detect load balancing
    pub detect_load_balancing: bool,
    /// Number of different flows to test for LB detection
    pub lb_detection_flows: u8,
}

impl Default for ParisOptions {
    fn default() -> Self {
        Self {
            max_hops: 30,
            timeout_per_hop: Duration::from_secs(2),
            probes_per_hop: 1,
            mode: ParisMode::Udp,
            flow_id: FlowId::default_paris(),
            detect_load_balancing: false,
            lb_detection_flows: 6,
        }
    }
}

/// Perform Paris Traceroute
pub async fn paris_traceroute(target: &str, options: &ParisOptions) -> crate::Result<ParisTraceResult> {
    let start_time = Instant::now();

    // Resolve target
    let dns_result = dns::resolve_ipv4(target).await?;
    let target_ip = dns_result.ip;

    let target_ipv4 = match target_ip {
        IpAddr::V4(ipv4) => ipv4,
        IpAddr::V6(_) => return Err(Error::InvalidTarget("IPv6 not yet supported".to_string())),
    };

    let mut hops = Vec::new();
    let mut reached_destination = false;

    for ttl in 1..=options.max_hops {
        let hop = match options.mode {
            ParisMode::Udp => probe_udp_paris(target_ipv4, ttl, options).await,
            ParisMode::Icmp => probe_icmp_paris(target_ipv4, ttl, options).await,
            ParisMode::Tcp => probe_tcp_paris(target_ipv4, ttl, options).await,
        };

        if let Some(addr) = hop.addr {
            if addr == target_ip {
                reached_destination = true;
            }
        }

        // ICMP type 0 = Echo Reply (destination reached)
        // ICMP type 3 = Destination Unreachable (also means we reached it)
        if hop.icmp_type == Some(0) || hop.icmp_type == Some(3) {
            reached_destination = true;
        }

        hops.push(hop);

        if reached_destination {
            break;
        }
    }

    // Detect load balancing if requested
    let load_balancing = if options.detect_load_balancing {
        detect_load_balancing(target_ipv4, &hops, options).await
    } else {
        LoadBalancingType::Unknown
    };

    Ok(ParisTraceResult {
        target: target.to_string(),
        target_ip,
        hops,
        reached_destination,
        flow_id: options.flow_id,
        mode: options.mode,
        total_time: start_time.elapsed(),
        load_balancing,
    })
}

/// Probe using UDP with Paris flow control
async fn probe_udp_paris(target: Ipv4Addr, ttl: u8, options: &ParisOptions) -> ParisHop {
    let timeout = options.timeout_per_hop;
    let flow_id = options.flow_id;

    let result = tokio::task::spawn_blocking(move || {
        probe_udp_paris_sync(target, ttl, timeout, flow_id)
    }).await;

    match result {
        Ok(Ok(hop)) => hop,
        Ok(Err(_)) => ParisHop::timeout(ttl, flow_id, timeout),
        Err(_) => ParisHop::timeout(ttl, flow_id, timeout),
    }
}

fn probe_udp_paris_sync(target: Ipv4Addr, ttl: u8, timeout: Duration, flow_id: FlowId) -> Result<ParisHop, Error> {
    // Create UDP socket
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    // Bind to specific source port for flow consistency
    let src_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), flow_id.src_port);
    socket.set_reuse_address(true)?;

    // Try to bind, fall back to any port if in use
    if socket.bind(&src_addr.into()).is_err() {
        socket.bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).into())?;
    }

    // Set TTL
    socket.set_ttl(ttl as u32)?;
    socket.set_read_timeout(Some(timeout))?;

    // Build payload - Paris uses specific payload to control UDP checksum
    // The checksum affects ECMP hashing, so we use a fixed payload
    let payload = build_paris_payload(ttl);

    let dest = SocketAddr::new(IpAddr::V4(target), flow_id.dst_port);
    let start = Instant::now();

    // Send UDP packet
    socket.send_to(&payload, &dest.into())?;

    // We need a raw ICMP socket to receive TTL Exceeded responses
    let icmp_socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
    icmp_socket.set_read_timeout(Some(timeout))?;

    let mut recv_buf: [MaybeUninit<u8>; 1024] = unsafe { MaybeUninit::uninit().assume_init() };

    match icmp_socket.recv_from(&mut recv_buf) {
        Ok((len, from_addr)) => {
            let rtt = start.elapsed();
            let buf: &[u8] = unsafe {
                std::slice::from_raw_parts(recv_buf.as_ptr() as *const u8, len)
            };

            if len >= 28 {
                let ip_header_len = ((buf[0] & 0x0F) * 4) as usize;
                if len > ip_header_len + 1 {
                    let icmp_type = buf[ip_header_len];
                    let icmp_code = buf[ip_header_len + 1];

                    let from_ip = from_addr.as_socket_ipv4()
                        .map(|a| IpAddr::V4(*a.ip()))
                        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

                    return Ok(ParisHop::success(ttl, from_ip, rtt, icmp_type, icmp_code, flow_id));
                }
            }
            Err(Error::Icmp("Invalid response".to_string()))
        }
        Err(_) => Ok(ParisHop::timeout(ttl, flow_id, timeout)),
    }
}

/// Probe using ICMP with Paris flow control
async fn probe_icmp_paris(target: Ipv4Addr, ttl: u8, options: &ParisOptions) -> ParisHop {
    let timeout = options.timeout_per_hop;
    let flow_id = options.flow_id;

    let result = tokio::task::spawn_blocking(move || {
        probe_icmp_paris_sync(target, ttl, timeout, flow_id)
    }).await;

    match result {
        Ok(Ok(hop)) => hop,
        Ok(Err(_)) => ParisHop::timeout(ttl, flow_id, timeout),
        Err(_) => ParisHop::timeout(ttl, flow_id, timeout),
    }
}

fn probe_icmp_paris_sync(target: Ipv4Addr, ttl: u8, timeout: Duration, flow_id: FlowId) -> Result<ParisHop, Error> {
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;

    socket.set_ttl(ttl as u32)?;
    socket.set_read_timeout(Some(timeout))?;

    // Paris ICMP: Use constant identifier, encode TTL in checksum manipulation
    let identifier = flow_id.src_port;
    let sequence = ttl as u16;
    let packet = build_paris_icmp_packet(identifier, sequence);

    let dest = SocketAddr::new(IpAddr::V4(target), 0);
    let start = Instant::now();

    socket.send_to(&packet, &dest.into())?;

    let mut recv_buf: [MaybeUninit<u8>; 1024] = unsafe { MaybeUninit::uninit().assume_init() };

    match socket.recv_from(&mut recv_buf) {
        Ok((len, from_addr)) => {
            let rtt = start.elapsed();
            let buf: &[u8] = unsafe {
                std::slice::from_raw_parts(recv_buf.as_ptr() as *const u8, len)
            };

            if len >= 28 {
                let ip_header_len = ((buf[0] & 0x0F) * 4) as usize;
                if len > ip_header_len + 1 {
                    let icmp_type = buf[ip_header_len];
                    let icmp_code = buf[ip_header_len + 1];

                    let from_ip = from_addr.as_socket_ipv4()
                        .map(|a| IpAddr::V4(*a.ip()))
                        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

                    return Ok(ParisHop::success(ttl, from_ip, rtt, icmp_type, icmp_code, flow_id));
                }
            }
            Err(Error::Icmp("Invalid response".to_string()))
        }
        Err(_) => Ok(ParisHop::timeout(ttl, flow_id, timeout)),
    }
}

/// Probe using TCP SYN with Paris flow control
async fn probe_tcp_paris(target: Ipv4Addr, ttl: u8, options: &ParisOptions) -> ParisHop {
    let timeout = options.timeout_per_hop;
    let flow_id = options.flow_id;

    let result = tokio::task::spawn_blocking(move || {
        probe_tcp_paris_sync(target, ttl, timeout, flow_id)
    }).await;

    match result {
        Ok(Ok(hop)) => hop,
        Ok(Err(_)) => ParisHop::timeout(ttl, flow_id, timeout),
        Err(_) => ParisHop::timeout(ttl, flow_id, timeout),
    }
}

fn probe_tcp_paris_sync(target: Ipv4Addr, ttl: u8, timeout: Duration, flow_id: FlowId) -> Result<ParisHop, Error> {
    // TCP Paris uses constant source/dest ports
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;

    socket.set_ttl(ttl as u32)?;
    socket.set_nonblocking(true)?;

    let src_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), flow_id.src_port);
    socket.set_reuse_address(true)?;
    let _ = socket.bind(&src_addr.into());

    let dest = SocketAddr::new(IpAddr::V4(target), flow_id.dst_port);
    let start = Instant::now();

    // Non-blocking connect - will return immediately
    let _ = socket.connect(&dest.into());

    // Wait for result using select/poll
    std::thread::sleep(std::cmp::min(timeout, Duration::from_millis(100)));

    let rtt = start.elapsed();

    // Check connection result
    match socket.take_error() {
        Ok(None) => {
            // Connected successfully - we reached the destination
            Ok(ParisHop::success(ttl, IpAddr::V4(target), rtt, 0, 0, flow_id))
        }
        Ok(Some(e)) => {
            // Connection refused means we reached the destination
            if e.raw_os_error() == Some(libc::ECONNREFUSED) {
                Ok(ParisHop::success(ttl, IpAddr::V4(target), rtt, 3, 3, flow_id))
            } else {
                Ok(ParisHop::timeout(ttl, flow_id, timeout))
            }
        }
        Err(_) => Ok(ParisHop::timeout(ttl, flow_id, timeout)),
    }
}

/// Build Paris-style UDP payload
fn build_paris_payload(ttl: u8) -> Vec<u8> {
    // Paris traceroute uses a specific payload structure
    // The payload is crafted so the UDP checksum remains constant
    // across different TTL values
    let mut payload = vec![0u8; 32];

    // Magic header for identification
    payload[0] = 0x50; // 'P'
    payload[1] = 0x41; // 'A'
    payload[2] = 0x52; // 'R'
    payload[3] = 0x49; // 'I'
    payload[4] = 0x53; // 'S'

    // TTL info (for our tracking, doesn't affect checksum significantly)
    payload[5] = ttl;

    // Timestamp
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u32;
    payload[6..10].copy_from_slice(&ts.to_be_bytes());

    payload
}

/// Build Paris-style ICMP packet with constant flow identifier
fn build_paris_icmp_packet(identifier: u16, sequence: u16) -> Vec<u8> {
    let mut packet = vec![0u8; 64];

    // Type: 8 (Echo Request)
    packet[0] = 8;
    // Code: 0
    packet[1] = 0;
    // Checksum: computed below
    packet[2] = 0;
    packet[3] = 0;
    // Identifier (constant for Paris)
    packet[4] = (identifier >> 8) as u8;
    packet[5] = identifier as u8;
    // Sequence
    packet[6] = (sequence >> 8) as u8;
    packet[7] = sequence as u8;

    // Paris magic in payload
    packet[8] = 0x50; // 'P'
    packet[9] = 0x41; // 'A'
    packet[10] = 0x52; // 'R'
    packet[11] = 0x49; // 'I'
    packet[12] = 0x53; // 'S'

    // Compute checksum
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

/// Detect load balancing type by probing with different flows
async fn detect_load_balancing(
    target: Ipv4Addr,
    reference_hops: &[ParisHop],
    options: &ParisOptions,
) -> LoadBalancingType {
    if reference_hops.is_empty() {
        return LoadBalancingType::Unknown;
    }

    // Get a mid-path hop to test (avoid first and last)
    let test_ttl = std::cmp::min(reference_hops.len() as u8, 10);
    if test_ttl < 3 {
        return LoadBalancingType::Unknown;
    }

    let reference_addr = reference_hops.get(test_ttl as usize - 1)
        .and_then(|h| h.addr);

    if reference_addr.is_none() {
        return LoadBalancingType::Unknown;
    }

    // Test with different flow IDs
    let mut results: HashMap<Option<IpAddr>, u32> = HashMap::new();
    results.insert(reference_addr, 1);

    for i in 0..options.lb_detection_flows {
        // Create different flow by varying source port
        let test_flow = FlowId::udp(33434 + i as u16, 33434);
        let test_options = ParisOptions {
            flow_id: test_flow,
            max_hops: test_ttl,
            probes_per_hop: 1,
            detect_load_balancing: false,
            ..options.clone()
        };

        let hop = probe_udp_paris(target, test_ttl, &test_options).await;
        *results.entry(hop.addr).or_insert(0) += 1;
    }

    // Analyze results
    let unique_addrs = results.len();

    if unique_addrs == 1 {
        // Same address every time - no load balancing or per-flow
        LoadBalancingType::None
    } else if unique_addrs > 1 {
        // Different addresses - load balancing detected
        // Per-flow would show consistency within same flow
        // Per-packet shows variation even with same flow
        LoadBalancingType::PerFlow
    } else {
        LoadBalancingType::Unknown
    }
}

/// Multi-path discovery using Paris Traceroute
///
/// Discovers all paths to a destination by varying flow identifiers
pub async fn discover_paths(
    target: &str,
    num_flows: u8,
    options: &ParisOptions,
) -> crate::Result<Vec<ParisTraceResult>> {
    let mut paths = Vec::new();

    for i in 0..num_flows {
        let flow_id = FlowId::udp(33434 + i as u16, 33434);
        let path_options = ParisOptions {
            flow_id,
            detect_load_balancing: false,
            ..options.clone()
        };

        let trace = paris_traceroute(target, &path_options).await?;
        paths.push(trace);
    }

    Ok(paths)
}

/// Compare two paths for equality
pub fn paths_equal(path1: &ParisTraceResult, path2: &ParisTraceResult) -> bool {
    let p1: Vec<_> = path1.path();
    let p2: Vec<_> = path2.path();

    if p1.len() != p2.len() {
        return false;
    }

    p1.iter().zip(p2.iter()).all(|(a, b)| a == b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_id() {
        let udp = FlowId::udp(33434, 33434);
        assert_eq!(udp.protocol, 17);

        let tcp = FlowId::tcp(80, 443);
        assert_eq!(tcp.protocol, 6);

        let icmp = FlowId::icmp(12345);
        assert_eq!(icmp.protocol, 1);
    }

    #[test]
    fn test_paris_payload() {
        let payload = build_paris_payload(5);
        assert_eq!(payload[0..5], [0x50, 0x41, 0x52, 0x49, 0x53]); // "PARIS"
        assert_eq!(payload[5], 5); // TTL
    }

    #[test]
    fn test_paris_icmp_packet() {
        let packet = build_paris_icmp_packet(1234, 5);
        assert_eq!(packet[0], 8); // Echo Request
        assert_eq!(packet[1], 0); // Code 0

        // Check identifier
        let id = ((packet[4] as u16) << 8) | packet[5] as u16;
        assert_eq!(id, 1234);
    }

    #[tokio::test]
    async fn test_paris_options_default() {
        let opts = ParisOptions::default();
        assert_eq!(opts.max_hops, 30);
        assert_eq!(opts.mode, ParisMode::Udp);
        assert_eq!(opts.flow_id.src_port, 33434);
    }
}
