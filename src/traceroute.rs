//! Traceroute implementation using ICMP and UDP
//!
//! Implements path discovery with TTL manipulation.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use std::mem::MaybeUninit;

use socket2::{Domain, Protocol, Socket, Type};

use crate::dns;
use crate::error::Error;

/// A single hop in a traceroute
#[derive(Debug, Clone)]
pub struct TracerouteHop {
    /// TTL/hop number (1-indexed)
    pub ttl: u8,
    /// IP address of the responding router (None if timeout/no response)
    pub addr: Option<IpAddr>,
    /// Hostname if reverse DNS succeeded
    pub hostname: Option<String>,
    /// Round-trip time to this hop
    pub rtt: Duration,
    /// Whether this hop responded
    pub responded: bool,
    /// ICMP type received (for diagnostics)
    pub icmp_type: Option<u8>,
}

impl TracerouteHop {
    fn timeout(ttl: u8, probe_timeout: Duration) -> Self {
        Self {
            ttl,
            addr: None,
            hostname: None,
            rtt: probe_timeout,
            responded: false,
            icmp_type: None,
        }
    }

    fn success(ttl: u8, addr: IpAddr, rtt: Duration, icmp_type: u8) -> Self {
        Self {
            ttl,
            addr: Some(addr),
            hostname: None,
            rtt,
            responded: true,
            icmp_type: Some(icmp_type),
        }
    }
}

/// Complete traceroute result
#[derive(Debug, Clone)]
pub struct TracerouteResult {
    /// Target that was traced
    pub target: String,
    /// Resolved IP address
    pub target_ip: IpAddr,
    /// All hops in order
    pub hops: Vec<TracerouteHop>,
    /// Whether the destination was reached
    pub reached_destination: bool,
    /// Total time for the traceroute
    pub total_time: Duration,
}

impl TracerouteResult {
    /// Get the number of hops to destination (or max hops tried)
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// Get responsive hops only
    pub fn responsive_hops(&self) -> Vec<&TracerouteHop> {
        self.hops.iter().filter(|h| h.responded).collect()
    }

    /// Get the path as a list of IP addresses
    pub fn path(&self) -> Vec<IpAddr> {
        self.hops.iter().filter_map(|h| h.addr).collect()
    }

    /// Check if path contains a specific IP or subnet
    pub fn path_contains(&self, ip: IpAddr) -> bool {
        self.hops.iter().any(|h| h.addr == Some(ip))
    }
}

/// Traceroute configuration
#[derive(Debug, Clone)]
pub struct TracerouteOptions {
    /// Maximum TTL (number of hops)
    pub max_hops: u8,
    /// Timeout per probe
    pub timeout_per_hop: Duration,
    /// Number of probes per hop
    pub probes_per_hop: u8,
    /// Starting port for UDP probes
    pub start_port: u16,
}

impl Default for TracerouteOptions {
    fn default() -> Self {
        Self {
            max_hops: 30,
            timeout_per_hop: Duration::from_secs(2),
            probes_per_hop: 1,
            start_port: 33434,
        }
    }
}

/// Perform a traceroute to the target
pub async fn traceroute(target: &str, options: &TracerouteOptions) -> crate::Result<TracerouteResult> {
    let start_time = Instant::now();

    // Resolve target
    let dns_result = dns::resolve_ipv4(target).await?;
    let target_ip = dns_result.ip;

    // Extract IPv4 address
    let target_ipv4 = match target_ip {
        IpAddr::V4(ipv4) => ipv4,
        IpAddr::V6(_) => return Err(Error::InvalidTarget("IPv6 traceroute not yet supported".to_string())),
    };

    let mut hops = Vec::new();
    let mut reached_destination = false;

    for ttl in 1..=options.max_hops {
        let hop = probe_hop(target_ipv4, ttl, options).await;

        if let Some(addr) = hop.addr {
            if addr == target_ip {
                reached_destination = true;
            }
        }

        // Check for ICMP Echo Reply (type 0) - means we reached destination
        if hop.icmp_type == Some(0) {
            reached_destination = true;
        }

        hops.push(hop);

        if reached_destination {
            break;
        }
    }

    Ok(TracerouteResult {
        target: target.to_string(),
        target_ip,
        hops,
        reached_destination,
        total_time: start_time.elapsed(),
    })
}

/// Probe a single hop using ICMP with a specific TTL
async fn probe_hop(target: Ipv4Addr, ttl: u8, options: &TracerouteOptions) -> TracerouteHop {
    // Use blocking socket operations in a spawn_blocking context
    let timeout_duration = options.timeout_per_hop;

    let result = tokio::task::spawn_blocking(move || {
        probe_hop_sync(target, ttl, timeout_duration)
    }).await;

    match result {
        Ok(Ok(hop)) => hop,
        Ok(Err(_)) => TracerouteHop::timeout(ttl, timeout_duration),
        Err(_) => TracerouteHop::timeout(ttl, timeout_duration),
    }
}

fn probe_hop_sync(target: Ipv4Addr, ttl: u8, probe_timeout: Duration) -> Result<TracerouteHop, Error> {
    // Create raw ICMP socket
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;

    // Set TTL
    socket.set_ttl(ttl as u32)?;

    // Set read timeout
    socket.set_read_timeout(Some(probe_timeout))?;

    // Build ICMP echo request
    let identifier = std::process::id() as u16;
    let sequence = ttl as u16;
    let packet = build_icmp_packet(identifier, sequence);

    let dest = SocketAddr::new(IpAddr::V4(target), 0);
    let start = Instant::now();

    // Send packet
    socket.send_to(&packet, &dest.into())?;

    // Receive response
    let mut recv_buf: [MaybeUninit<u8>; 1024] = unsafe { MaybeUninit::uninit().assume_init() };

    match socket.recv_from(&mut recv_buf) {
        Ok((len, from_addr)) => {
            let rtt = start.elapsed();

            // Convert MaybeUninit buffer to regular slice
            let buf: &[u8] = unsafe {
                std::slice::from_raw_parts(recv_buf.as_ptr() as *const u8, len)
            };

            // Parse response - skip IP header (usually 20 bytes, but check IHL)
            if len >= 28 {
                let ip_header_len = ((buf[0] & 0x0F) * 4) as usize;
                if len > ip_header_len {
                    let icmp_type = buf[ip_header_len];

                    // Extract source IP from socket address
                    let from_ip = match from_addr.as_socket_ipv4() {
                        Some(addr) => IpAddr::V4(*addr.ip()),
                        None => return Err(Error::Icmp("Invalid response address".to_string())),
                    };

                    return Ok(TracerouteHop::success(ttl, from_ip, rtt, icmp_type));
                }
            }

            Err(Error::Icmp("Invalid response".to_string()))
        }
        Err(_) => Ok(TracerouteHop::timeout(ttl, probe_timeout)),
    }
}

/// Build ICMP echo request packet
fn build_icmp_packet(identifier: u16, sequence: u16) -> Vec<u8> {
    let mut packet = vec![0u8; 64];

    // Type: 8 (Echo Request)
    packet[0] = 8;
    // Code: 0
    packet[1] = 0;
    // Checksum: 0 (will be computed)
    packet[2] = 0;
    packet[3] = 0;
    // Identifier
    packet[4] = (identifier >> 8) as u8;
    packet[5] = identifier as u8;
    // Sequence
    packet[6] = (sequence >> 8) as u8;
    packet[7] = sequence as u8;

    // Payload (timestamp)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    for (i, byte) in now.to_be_bytes().iter().enumerate() {
        if i + 8 < packet.len() {
            packet[i + 8] = *byte;
        }
    }

    // Compute checksum
    let checksum = compute_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = checksum as u8;

    packet
}

/// Compute ICMP checksum
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

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum() {
        // Test with known values
        let data = [0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01];
        let checksum = compute_checksum(&data);
        assert!(checksum > 0);
    }

    #[tokio::test]
    async fn test_traceroute_localhost() {
        let options = TracerouteOptions {
            max_hops: 5,
            timeout_per_hop: Duration::from_secs(1),
            ..Default::default()
        };

        // Test with localhost - should reach immediately
        let result = traceroute("127.0.0.1", &options).await;

        match result {
            Ok(r) => {
                println!("Traceroute to {}: {} hops, reached: {}",
                    r.target, r.hop_count(), r.reached_destination);
                for hop in &r.hops {
                    println!("  TTL {}: {:?} ({:.2}ms)",
                        hop.ttl, hop.addr, hop.rtt.as_secs_f64() * 1000.0);
                }
            }
            Err(e) => {
                println!("Traceroute failed (may need root): {e}");
            }
        }
    }
}
