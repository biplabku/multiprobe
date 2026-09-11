//! ASN lookup using Team Cymru DNS service
//!
//! Team Cymru provides free IP-to-ASN mapping via DNS queries.
//! Query format: reversed-IP.origin.asn.cymru.com

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use tokio::sync::RwLock;

/// Error types for ASN lookup
#[derive(Debug, thiserror::Error)]
pub enum AsnLookupError {
    #[error("DNS resolution failed: {0}")]
    DnsError(String),

    #[error("Invalid response format: {0}")]
    ParseError(String),

    #[error("No ASN found for IP: {0}")]
    NotFound(IpAddr),

    #[error("Private/reserved IP address: {0}")]
    PrivateAddress(IpAddr),
}

/// Information about an Autonomous System
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnInfo {
    /// AS Number
    pub asn: u32,
    /// BGP prefix this IP belongs to
    pub prefix: String,
    /// Country code (2-letter ISO)
    pub country: Option<String>,
    /// Registry (ARIN, RIPE, APNIC, etc.)
    pub registry: Option<String>,
    /// Allocation date
    pub allocated: Option<String>,
    /// AS Name/Description
    pub as_name: Option<String>,
}

impl AsnInfo {
    /// Check if this is a well-known transit AS
    pub fn is_transit(&self) -> bool {
        // Major transit providers
        matches!(self.asn,
            174 |    // Cogent
            1299 |   // Telia
            2914 |   // NTT
            3257 |   // GTT
            3356 |   // Lumen
            6453 |   // Tata
            6461 |   // Zayo
            6762 |   // Telecom Italia
            6830 |   // Liberty Global
            7018 |   // AT&T
            12956    // Telefonica
        )
    }

    /// Check if this is a major cloud provider
    pub fn is_cloud_provider(&self) -> bool {
        matches!(self.asn,
            15169 |  // Google
            16509 |  // Amazon
            8075 |   // Microsoft
            13335 |  // Cloudflare
            20940 |  // Akamai
            54113 |  // Fastly
            14618 |  // Amazon (alternate)
            396982   // Google Cloud
        )
    }
}

/// ASN lookup service using Team Cymru DNS
pub struct AsnLookup {
    resolver: TokioAsyncResolver,
    cache: Arc<RwLock<HashMap<IpAddr, AsnInfo>>>,
}

impl AsnLookup {
    /// Create a new ASN lookup service
    pub async fn new() -> Result<Self, AsnLookupError> {
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );

        Ok(Self {
            resolver,
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Look up ASN information for an IP address
    pub async fn lookup(&self, ip: IpAddr) -> Result<AsnInfo, AsnLookupError> {
        // Check if private/reserved
        if is_private_ip(ip) {
            return Err(AsnLookupError::PrivateAddress(ip));
        }

        // Check cache
        {
            let cache = self.cache.read().await;
            if let Some(info) = cache.get(&ip) {
                return Ok(info.clone());
            }
        }

        // Query Team Cymru DNS
        let info = self.query_cymru(ip).await?;

        // Cache result
        {
            let mut cache = self.cache.write().await;
            cache.insert(ip, info.clone());
        }

        Ok(info)
    }

    /// Query Team Cymru for ASN info
    async fn query_cymru(&self, ip: IpAddr) -> Result<AsnInfo, AsnLookupError> {
        let query_name = match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                format!(
                    "{}.{}.{}.{}.origin.asn.cymru.com",
                    octets[3], octets[2], octets[1], octets[0]
                )
            }
            IpAddr::V6(_) => {
                return Err(AsnLookupError::DnsError(
                    "IPv6 lookup not yet implemented".to_string()
                ));
            }
        };

        // Query TXT record
        let response = self.resolver.txt_lookup(&query_name).await
            .map_err(|e| AsnLookupError::DnsError(e.to_string()))?;

        // Parse response: "ASN | Prefix | Country | Registry | Allocated"
        for txt in response.iter() {
            let txt_str = txt.to_string();
            let parts: Vec<&str> = txt_str.split('|').map(|s| s.trim()).collect();

            if parts.len() >= 2 {
                let asn: u32 = parts[0].trim()
                    .parse()
                    .map_err(|_| AsnLookupError::ParseError(
                        format!("Invalid ASN: {}", parts[0])
                    ))?;

                let mut info = AsnInfo {
                    asn,
                    prefix: parts[1].to_string(),
                    country: parts.get(2).map(|s| s.to_string()),
                    registry: parts.get(3).map(|s| s.to_string()),
                    allocated: parts.get(4).map(|s| s.to_string()),
                    as_name: None,
                };

                // Optionally look up AS name
                if let Ok(name) = self.lookup_as_name(asn).await {
                    info.as_name = Some(name);
                }

                return Ok(info);
            }
        }

        Err(AsnLookupError::NotFound(ip))
    }

    /// Look up AS name from Team Cymru
    async fn lookup_as_name(&self, asn: u32) -> Result<String, AsnLookupError> {
        let query_name = format!("AS{}.asn.cymru.com", asn);

        let response = self.resolver.txt_lookup(&query_name).await
            .map_err(|e| AsnLookupError::DnsError(e.to_string()))?;

        // Parse: "ASN | Country | Registry | Allocated | AS Name"
        for txt in response.iter() {
            let txt_str = txt.to_string();
            let parts: Vec<&str> = txt_str.split('|').map(|s| s.trim()).collect();

            if parts.len() >= 5 {
                return Ok(parts[4].to_string());
            }
        }

        Err(AsnLookupError::NotFound(IpAddr::V4(Ipv4Addr::UNSPECIFIED)))
    }

    /// Batch lookup for multiple IPs
    pub async fn lookup_batch(&self, ips: &[IpAddr]) -> HashMap<IpAddr, Result<AsnInfo, String>> {
        let mut results = HashMap::new();

        for ip in ips {
            let result = self.lookup(*ip).await
                .map_err(|e| e.to_string());
            results.insert(*ip, result);
        }

        results
    }

    /// Clear the cache
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }

    /// Get cache size
    pub async fn cache_size(&self) -> usize {
        let cache = self.cache.read().await;
        cache.len()
    }
}

/// Check if an IP is private/reserved
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private() ||
            ipv4.is_loopback() ||
            ipv4.is_link_local() ||
            ipv4.is_broadcast() ||
            ipv4.is_documentation() ||
            ipv4.is_unspecified() ||
            // CGNAT range
            (ipv4.octets()[0] == 100 && ipv4.octets()[1] >= 64 && ipv4.octets()[1] <= 127)
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback() ||
            ipv6.is_unspecified()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_ip_detection() {
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)))); // CGNAT

        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }

    #[test]
    fn test_transit_as_detection() {
        let cogent = AsnInfo {
            asn: 174,
            prefix: "1.0.0.0/8".to_string(),
            country: Some("US".to_string()),
            registry: None,
            allocated: None,
            as_name: Some("COGENT".to_string()),
        };
        assert!(cogent.is_transit());

        let google = AsnInfo {
            asn: 15169,
            prefix: "8.8.8.0/24".to_string(),
            country: Some("US".to_string()),
            registry: None,
            allocated: None,
            as_name: Some("GOOGLE".to_string()),
        };
        assert!(!google.is_transit());
        assert!(google.is_cloud_provider());
    }

    #[tokio::test]
    async fn test_asn_lookup_google() {
        let lookup = AsnLookup::new().await.unwrap();

        // Google DNS - should be AS15169
        let result = lookup.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).await;

        match result {
            Ok(info) => {
                assert_eq!(info.asn, 15169);
                println!("AS{}: {} ({})", info.asn,
                    info.as_name.unwrap_or_default(),
                    info.prefix);
            }
            Err(e) => {
                println!("Lookup failed (may need network): {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_private_ip_error() {
        let lookup = AsnLookup::new().await.unwrap();

        let result = lookup.lookup(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))).await;
        assert!(matches!(result, Err(AsnLookupError::PrivateAddress(_))));
    }
}
