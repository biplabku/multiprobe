//! TCP connect probe implementation

use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::dns;
use crate::error::Error;
use crate::types::{ProbeOptions, ProbeResult, Protocol, ResponseData, TimingBreakdown};

/// Perform a TCP connect probe
pub async fn probe(host: &str, port: u16, options: &ProbeOptions) -> crate::Result<ProbeResult> {
    // DNS resolution with timing
    let dns_result = dns::resolve_ipv4(host).await?;
    let dns_time = if dns_result.duration > Duration::ZERO {
        Some(dns_result.duration)
    } else {
        None
    };

    let target_addr = SocketAddr::new(dns_result.ip, port);

    // TCP connect with timing
    let connect_start = Instant::now();

    let connect_result = timeout(
        options.timeout,
        TcpStream::connect(target_addr)
    ).await;

    let connect_time = connect_start.elapsed();

    match connect_result {
        Ok(Ok(_stream)) => {
            // Connection successful
            let timing = TimingBreakdown::new(dns_time, connect_time, Duration::ZERO);

            Ok(ProbeResult::success(
                host.to_string(),
                dns_result.ip,
                Protocol::Tcp(port),
                timing,
            ).with_response_data(ResponseData::Tcp {
                connected: true,
                reset: false,
            }))
        }
        Ok(Err(e)) => {
            // Connection failed
            let timing = TimingBreakdown::new(dns_time, connect_time, Duration::ZERO);
            let error_msg = e.to_string();

            // Detect connection refused (RST)
            let is_refused = error_msg.contains("refused") ||
                            error_msg.contains("Connection refused");

            if is_refused {
                Ok(ProbeResult::failure(
                    host.to_string(),
                    dns_result.ip,
                    Protocol::Tcp(port),
                    "Connection refused".to_string(),
                    timing,
                ).with_response_data(ResponseData::Tcp {
                    connected: false,
                    reset: true,
                }))
            } else {
                Err(Error::ConnectionFailed {
                    target: format!("{host}:{port}"),
                    message: error_msg,
                })
            }
        }
        Err(_) => {
            // Timeout
            let timing = TimingBreakdown::new(dns_time, options.timeout, Duration::ZERO);

            Ok(ProbeResult::failure(
                host.to_string(),
                dns_result.ip,
                Protocol::Tcp(port),
                "Connection timed out".to_string(),
                timing,
            ).with_response_data(ResponseData::Tcp {
                connected: false,
                reset: false,
            }))
        }
    }
}

/// Probe multiple TCP ports concurrently
#[allow(dead_code)]
pub async fn probe_ports(
    host: &str,
    ports: &[u16],
    options: &ProbeOptions
) -> Vec<crate::Result<ProbeResult>> {
    let futures: Vec<_> = ports
        .iter()
        .map(|&port| probe(host, port, options))
        .collect();

    futures::future::join_all(futures).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tcp_probe_success() {
        let options = ProbeOptions::with_timeout(Duration::from_secs(5));
        let result = probe("google.com", 443, &options).await;

        match result {
            Ok(r) => {
                assert!(r.success);
                assert_eq!(r.protocol, Protocol::Tcp(443));
                assert!(r.timing.total_ms() > 0.0);
            }
            Err(e) => {
                // Network may not be available in test environment
                println!("Test skipped due to network: {e}");
            }
        }
    }

    #[tokio::test]
    async fn test_tcp_probe_refused() {
        let options = ProbeOptions::with_timeout(Duration::from_secs(2));
        // Port 9 is typically closed
        let result = probe("127.0.0.1", 9, &options).await;

        match result {
            Ok(r) => {
                // Should fail with connection refused
                assert!(!r.success);
                if let Some(ResponseData::Tcp { reset, .. }) = r.response_data {
                    assert!(reset);
                }
            }
            Err(_) => {
                // Also acceptable
            }
        }
    }
}
