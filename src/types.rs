//! Core types for multiprobe

use std::net::IpAddr;
use std::time::Duration;

/// Protocol used for probing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// ICMP Echo Request/Reply
    Icmp,
    /// TCP connection probe
    Tcp(u16),
    /// UDP packet probe
    Udp(u16),
}

impl Protocol {
    /// Get the port number if applicable
    pub fn port(&self) -> Option<u16> {
        match self {
            Protocol::Icmp => None,
            Protocol::Tcp(port) | Protocol::Udp(port) => Some(*port),
        }
    }

    /// Get a human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Protocol::Icmp => "ICMP",
            Protocol::Tcp(_) => "TCP",
            Protocol::Udp(_) => "UDP",
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Icmp => write!(f, "ICMP"),
            Protocol::Tcp(port) => write!(f, "TCP/{port}"),
            Protocol::Udp(port) => write!(f, "UDP/{port}"),
        }
    }
}

/// Timing breakdown for a probe operation
#[derive(Debug, Clone, Default)]
pub struct TimingBreakdown {
    /// Time spent on DNS resolution (None if IP was provided directly)
    pub dns_time: Option<Duration>,
    /// Time to establish connection (TCP) or send packet (ICMP/UDP)
    pub connect_time: Duration,
    /// Time to receive response
    pub response_time: Duration,
    /// Total round-trip time
    pub total_time: Duration,
}

impl TimingBreakdown {
    /// Create a new timing breakdown
    pub fn new(
        dns_time: Option<Duration>,
        connect_time: Duration,
        response_time: Duration,
    ) -> Self {
        let total_time = dns_time.unwrap_or_default() + connect_time + response_time;
        Self {
            dns_time,
            connect_time,
            response_time,
            total_time,
        }
    }

    /// Get DNS time in milliseconds
    pub fn dns_ms(&self) -> Option<f64> {
        self.dns_time.map(|d| d.as_secs_f64() * 1000.0)
    }

    /// Get connect time in milliseconds
    pub fn connect_ms(&self) -> f64 {
        self.connect_time.as_secs_f64() * 1000.0
    }

    /// Get response time in milliseconds
    pub fn response_ms(&self) -> f64 {
        self.response_time.as_secs_f64() * 1000.0
    }

    /// Get total time in milliseconds
    pub fn total_ms(&self) -> f64 {
        self.total_time.as_secs_f64() * 1000.0
    }
}

/// Result of a single probe operation
#[derive(Debug, Clone)]
pub struct ProbeResult {
    /// Target that was probed
    pub target: String,
    /// Resolved IP address
    pub resolved_ip: IpAddr,
    /// Protocol used
    pub protocol: Protocol,
    /// Whether the probe succeeded
    pub success: bool,
    /// Timing breakdown
    pub timing: TimingBreakdown,
    /// TTL/hop count from response (if available)
    pub ttl: Option<u8>,
    /// Error message if probe failed
    pub error: Option<String>,
    /// Response data (protocol-specific)
    pub response_data: Option<ResponseData>,
}

/// Protocol-specific response data
#[derive(Debug, Clone)]
pub enum ResponseData {
    /// ICMP response data
    Icmp {
        /// ICMP sequence number
        sequence: u16,
        /// Identifier
        identifier: u16,
    },
    /// TCP response data
    Tcp {
        /// Whether connection was established
        connected: bool,
        /// Whether RST was received (port closed)
        reset: bool,
    },
    /// UDP response data
    Udp {
        /// Bytes received in response
        bytes_received: usize,
        /// Whether ICMP port unreachable was received
        port_unreachable: bool,
    },
}

impl ProbeResult {
    /// Create a successful probe result
    pub fn success(
        target: String,
        resolved_ip: IpAddr,
        protocol: Protocol,
        timing: TimingBreakdown,
    ) -> Self {
        Self {
            target,
            resolved_ip,
            protocol,
            success: true,
            timing,
            ttl: None,
            error: None,
            response_data: None,
        }
    }

    /// Create a failed probe result
    pub fn failure(
        target: String,
        resolved_ip: IpAddr,
        protocol: Protocol,
        error: String,
        timing: TimingBreakdown,
    ) -> Self {
        Self {
            target,
            resolved_ip,
            protocol,
            success: false,
            timing,
            ttl: None,
            error: Some(error),
            response_data: None,
        }
    }

    /// Set TTL
    pub fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set response data
    pub fn with_response_data(mut self, data: ResponseData) -> Self {
        self.response_data = Some(data);
        self
    }
}

/// Options for probe operations
#[derive(Debug, Clone)]
pub struct ProbeOptions {
    /// Timeout for the entire operation
    pub timeout: Duration,
    /// Number of retries on failure
    pub retries: u32,
    /// TTL to set on outgoing packets
    pub ttl: Option<u8>,
    /// Source IP to bind to
    pub source_ip: Option<IpAddr>,
    /// Source port to bind to (TCP/UDP only)
    pub source_port: Option<u16>,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            retries: 0,
            ttl: None,
            source_ip: None,
            source_port: None,
        }
    }
}

impl ProbeOptions {
    /// Create options with specified timeout
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            timeout,
            ..Default::default()
        }
    }
}

/// Result of multi-protocol probe
#[derive(Debug, Clone)]
pub struct MultiProbeResult {
    /// Target that was probed
    pub target: String,
    /// Individual probe results by protocol
    pub results: Vec<ProbeResult>,
    /// Path classification based on results
    pub classification: Option<PathClassification>,
}

impl MultiProbeResult {
    /// Get result for a specific protocol
    pub fn get(&self, protocol: &Protocol) -> Option<&ProbeResult> {
        self.results.iter().find(|r| &r.protocol == protocol)
    }

    /// Check if ICMP succeeded
    pub fn icmp_success(&self) -> bool {
        self.results.iter()
            .any(|r| matches!(r.protocol, Protocol::Icmp) && r.success)
    }

    /// Check if TCP succeeded for a specific port
    pub fn tcp_success(&self, port: u16) -> bool {
        self.results.iter()
            .any(|r| matches!(r.protocol, Protocol::Tcp(p) if p == port) && r.success)
    }

    /// Check if UDP succeeded for a specific port
    pub fn udp_success(&self, port: u16) -> bool {
        self.results.iter()
            .any(|r| matches!(r.protocol, Protocol::Udp(p) if p == port) && r.success)
    }

    /// Classify the path based on probe results
    pub fn classify(&self) -> String {
        if let Some(ref class) = self.classification {
            class.to_string()
        } else {
            "Unknown".to_string()
        }
    }
}

/// Path classification based on multi-protocol probe results
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathClassification {
    /// All protocols succeed - direct/open path
    Open,
    /// ICMP blocked, TCP/UDP open - firewall with ICMP filter
    IcmpFiltered,
    /// Only specific ports open - selective firewall
    SelectiveFirewall {
        open_ports: Vec<u16>,
        closed_ports: Vec<u16>,
    },
    /// All protocols blocked - host down or fully firewalled
    Blocked,
    /// ICMP succeeds, TCP fails - possible TCP-specific filtering
    TcpFiltered,
    /// Mixed results indicating NAT or load balancer
    NatDetected,
    /// Unable to classify
    Unknown,
}

impl std::fmt::Display for PathClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathClassification::Open => write!(f, "Open (all protocols pass)"),
            PathClassification::IcmpFiltered => write!(f, "ICMP Filtered (TCP/UDP open)"),
            PathClassification::SelectiveFirewall { open_ports, closed_ports } => {
                write!(f, "Selective Firewall (open: {open_ports:?}, closed: {closed_ports:?})")
            }
            PathClassification::Blocked => write!(f, "Blocked (all protocols fail)"),
            PathClassification::TcpFiltered => write!(f, "TCP Filtered (ICMP open)"),
            PathClassification::NatDetected => write!(f, "NAT/Load Balancer detected"),
            PathClassification::Unknown => write!(f, "Unknown"),
        }
    }
}
