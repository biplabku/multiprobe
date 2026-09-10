//! ICMP ping probe implementation

use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use socket2::{Domain, Protocol as SockProtocol, Socket, Type};
use tokio::time::timeout;

use crate::dns;
use crate::error::Error;
use crate::types::{ProbeOptions, ProbeResult, Protocol, ResponseData, TimingBreakdown};

const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;

/// Build an ICMP echo request packet
fn build_icmp_packet(identifier: u16, sequence: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(8 + payload.len());

    // Type: Echo Request
    packet.push(ICMP_ECHO_REQUEST);
    // Code: 0
    packet.push(0);
    // Checksum placeholder
    packet.push(0);
    packet.push(0);
    // Identifier
    packet.push((identifier >> 8) as u8);
    packet.push(identifier as u8);
    // Sequence number
    packet.push((sequence >> 8) as u8);
    packet.push(sequence as u8);
    // Payload
    packet.extend_from_slice(payload);

    // Calculate checksum
    let checksum = calculate_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = checksum as u8;

    packet
}

/// Calculate ICMP checksum
fn calculate_checksum(data: &[u8]) -> u16 {
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

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// Parse ICMP echo reply
fn parse_icmp_reply(data: &[u8]) -> Option<(u8, u16, u16)> {
    // Skip IP header (usually 20 bytes, but check IHL)
    if data.len() < 20 {
        return None;
    }

    let ihl = (data[0] & 0x0F) as usize * 4;
    if data.len() < ihl + 8 {
        return None;
    }

    let icmp_data = &data[ihl..];
    let icmp_type = icmp_data[0];
    let identifier = ((icmp_data[4] as u16) << 8) | (icmp_data[5] as u16);
    let sequence = ((icmp_data[6] as u16) << 8) | (icmp_data[7] as u16);

    Some((icmp_type, identifier, sequence))
}

/// Perform an ICMP ping probe
pub async fn probe(host: &str, options: &ProbeOptions) -> crate::Result<ProbeResult> {
    // DNS resolution with timing
    let dns_result = dns::resolve_ipv4(host).await?;
    let dns_time = if dns_result.duration > Duration::ZERO {
        Some(dns_result.duration)
    } else {
        None
    };

    let target_ip = match dns_result.ip {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => {
            return Err(Error::InvalidTarget("IPv6 not supported for ICMP yet".to_string()));
        }
    };

    // Create raw socket
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(SockProtocol::ICMPV4))
        .map_err(|e| {
            if e.raw_os_error() == Some(1) || e.raw_os_error() == Some(13) {
                Error::PermissionDenied
            } else {
                Error::SocketCreation(e)
            }
        })?;

    socket.set_nonblocking(true)?;

    // Set TTL if specified
    if let Some(ttl) = options.ttl {
        socket.set_ttl(ttl as u32)?;
    }

    // Build ICMP packet
    let identifier = std::process::id() as u16;
    let sequence = 1u16;
    let payload = b"multiprobe";
    let packet = build_icmp_packet(identifier, sequence, payload);

    let dest_addr = SocketAddr::new(IpAddr::V4(target_ip), 0);

    // Send ICMP packet and measure time
    let send_start = Instant::now();

    socket.send_to(&packet, &dest_addr.into())?;

    // Wait for reply
    let mut recv_buf: [MaybeUninit<u8>; 1024] = unsafe { MaybeUninit::uninit().assume_init() };

    let recv_result = timeout(options.timeout, async {
        loop {
            // Use tokio's async I/O
            tokio::time::sleep(Duration::from_millis(1)).await;

            match socket.recv_from(&mut recv_buf) {
                Ok((len, _addr)) => {
                    // Convert MaybeUninit buffer to regular slice
                    let data: &[u8] = unsafe {
                        std::slice::from_raw_parts(recv_buf.as_ptr() as *const u8, len)
                    };
                    if let Some((icmp_type, recv_id, recv_seq)) = parse_icmp_reply(data) {
                        if icmp_type == ICMP_ECHO_REPLY && recv_id == identifier && recv_seq == sequence {
                            return Ok(len);
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
    }).await;

    let rtt = send_start.elapsed();

    match recv_result {
        Ok(Ok(_len)) => {
            let timing = TimingBreakdown::new(dns_time, Duration::ZERO, rtt);

            Ok(ProbeResult::success(
                host.to_string(),
                dns_result.ip,
                Protocol::Icmp,
                timing,
            ).with_response_data(ResponseData::Icmp {
                sequence,
                identifier,
            }))
        }
        Ok(Err(e)) => {
            let _timing = TimingBreakdown::new(dns_time, Duration::ZERO, rtt);
            Err(Error::Icmp(e.to_string()))
        }
        Err(_) => {
            // Timeout
            let timing = TimingBreakdown::new(dns_time, Duration::ZERO, options.timeout);

            Ok(ProbeResult::failure(
                host.to_string(),
                dns_result.ip,
                Protocol::Icmp,
                "Request timed out".to_string(),
                timing,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_icmp_packet() {
        let packet = build_icmp_packet(1234, 1, b"test");
        assert_eq!(packet[0], ICMP_ECHO_REQUEST);
        assert_eq!(packet[1], 0); // Code
        assert_eq!(packet.len(), 8 + 4); // Header + payload
    }

    #[test]
    fn test_checksum() {
        let data = [0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01];
        let checksum = calculate_checksum(&data);
        assert!(checksum > 0);
    }
}
