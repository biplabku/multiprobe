//! DNS resolution with timing

use std::net::IpAddr;
use std::time::{Duration, Instant};
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use crate::error::Error;

/// DNS resolution result with timing
#[derive(Debug, Clone)]
pub struct DnsResult {
    /// Resolved IP address
    pub ip: IpAddr,
    /// Time taken for resolution
    pub duration: Duration,
}

/// Resolve a hostname to an IP address with timing
#[allow(dead_code)]
pub async fn resolve(host: &str) -> Result<DnsResult, Error> {
    // Check if already an IP address
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(DnsResult {
            ip,
            duration: Duration::ZERO,
        });
    }

    let start = Instant::now();

    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    );

    let response = resolver
        .lookup_ip(host)
        .await
        .map_err(|e| Error::DnsResolution {
            host: host.to_string(),
            message: e.to_string(),
        })?;

    let ip = response
        .iter()
        .next()
        .ok_or_else(|| Error::DnsResolution {
            host: host.to_string(),
            message: "No addresses returned".to_string(),
        })?;

    Ok(DnsResult {
        ip,
        duration: start.elapsed(),
    })
}

/// Resolve a hostname, preferring IPv4
pub async fn resolve_ipv4(host: &str) -> Result<DnsResult, Error> {
    // Validate input
    let host = host.trim();
    if host.is_empty() {
        return Err(Error::DnsResolution {
            host: host.to_string(),
            message: "Empty hostname".to_string(),
        });
    }

    // Check for obviously invalid characters
    if host.contains(['<', '>', ' ', '\n', '\t']) {
        return Err(Error::DnsResolution {
            host: host.to_string(),
            message: "Invalid characters in hostname".to_string(),
        });
    }

    // Check if already an IP address
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(DnsResult {
            ip,
            duration: Duration::ZERO,
        });
    }

    let start = Instant::now();

    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    );

    let response = resolver
        .lookup_ip(host)
        .await
        .map_err(|e| Error::DnsResolution {
            host: host.to_string(),
            message: e.to_string(),
        })?;

    // Prefer IPv4
    let ip = response
        .iter()
        .find(|ip| ip.is_ipv4())
        .or_else(|| response.iter().next())
        .ok_or_else(|| Error::DnsResolution {
            host: host.to_string(),
            message: "No addresses returned".to_string(),
        })?;

    Ok(DnsResult {
        ip,
        duration: start.elapsed(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resolve_ip_direct() {
        let result = resolve("8.8.8.8").await.unwrap();
        assert_eq!(result.ip.to_string(), "8.8.8.8");
        assert_eq!(result.duration, Duration::ZERO);
    }

    #[tokio::test]
    async fn test_resolve_hostname() {
        let result = resolve("google.com").await.unwrap();
        assert!(result.duration >= Duration::ZERO);
    }
}
