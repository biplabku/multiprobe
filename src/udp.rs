//! UDP probe implementation

use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::dns;
use crate::error::Error;
use crate::types::{ProbeOptions, ProbeResult, Protocol, ResponseData, TimingBreakdown};

/// Perform a UDP probe
pub async fn probe(host: &str, port: u16, options: &ProbeOptions) -> crate::Result<ProbeResult> {
    // DNS resolution with timing
    let dns_result = dns::resolve_ipv4(host).await?;
    let dns_time = if dns_result.duration > Duration::ZERO {
        Some(dns_result.duration)
    } else {
        None
    };

    let target_addr = SocketAddr::new(dns_result.ip, port);

    // Create UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0").await?;

    // Connect to target (sets default destination)
    socket.connect(target_addr).await?;

    // Send probe packet
    let probe_data = b"multiprobe";
    let send_start = Instant::now();

    socket.send(probe_data).await?;

    let connect_time = send_start.elapsed();

    // Wait for response
    let mut recv_buf = [0u8; 1024];

    let recv_result = timeout(options.timeout, socket.recv(&mut recv_buf)).await;

    let response_time = send_start.elapsed() - connect_time;

    match recv_result {
        Ok(Ok(len)) => {
            // Got a response
            let timing = TimingBreakdown::new(dns_time, connect_time, response_time);

            Ok(ProbeResult::success(
                host.to_string(),
                dns_result.ip,
                Protocol::Udp(port),
                timing,
            ).with_response_data(ResponseData::Udp {
                bytes_received: len,
                port_unreachable: false,
            }))
        }
        Ok(Err(e)) => {
            // Error receiving - could be ICMP port unreachable
            let timing = TimingBreakdown::new(dns_time, connect_time, response_time);
            let error_msg = e.to_string();

            let port_unreachable = error_msg.contains("refused") ||
                                   error_msg.contains("unreachable");

            if port_unreachable {
                Ok(ProbeResult::failure(
                    host.to_string(),
                    dns_result.ip,
                    Protocol::Udp(port),
                    "Port unreachable".to_string(),
                    timing,
                ).with_response_data(ResponseData::Udp {
                    bytes_received: 0,
                    port_unreachable: true,
                }))
            } else {
                Err(Error::ConnectionFailed {
                    target: format!("{host}:{port}"),
                    message: error_msg,
                })
            }
        }
        Err(_) => {
            // Timeout - for UDP this often means the packet was accepted
            // (no ICMP error returned)
            let timing = TimingBreakdown::new(dns_time, connect_time, options.timeout);

            // UDP timeout is ambiguous - could be:
            // 1. Packet accepted (service doesn't respond to our probe)
            // 2. Packet filtered (firewall dropped it)
            // 3. Packet lost
            // We mark as "success" since no error was returned
            Ok(ProbeResult::success(
                host.to_string(),
                dns_result.ip,
                Protocol::Udp(port),
                timing,
            ).with_response_data(ResponseData::Udp {
                bytes_received: 0,
                port_unreachable: false,
            }))
        }
    }
}

/// Probe DNS specifically (UDP port 53)
#[allow(dead_code)]
pub async fn probe_dns(host: &str, options: &ProbeOptions) -> crate::Result<ProbeResult> {
    probe(host, 53, options).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_udp_probe_dns() {
        let options = ProbeOptions::with_timeout(Duration::from_secs(2));
        let result = probe("8.8.8.8", 53, &options).await;

        match result {
            Ok(r) => {
                // DNS port should accept our packet (or timeout without error)
                assert!(r.timing.total_ms() > 0.0);
            }
            Err(e) => {
                println!("Test skipped due to network: {e}");
            }
        }
    }
}
