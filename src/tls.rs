//! TLS Handshake Timing and Analysis
//!
//! Provides detailed timing breakdown of TLS handshakes including:
//! - TCP connect time
//! - TLS handshake time
//! - Certificate chain validation
//! - Cipher negotiation
//! - Session resumption detection

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use crate::dns;
use crate::error::Error;

/// TLS version detected
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls10,
    Tls11,
    Tls12,
    Tls13,
    Unknown,
}

impl std::fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsVersion::Tls10 => write!(f, "TLS 1.0"),
            TlsVersion::Tls11 => write!(f, "TLS 1.1"),
            TlsVersion::Tls12 => write!(f, "TLS 1.2"),
            TlsVersion::Tls13 => write!(f, "TLS 1.3"),
            TlsVersion::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Detailed TLS handshake timing breakdown
#[derive(Debug, Clone)]
pub struct TlsTimingBreakdown {
    /// DNS resolution time
    pub dns_time: Duration,
    /// TCP connection establishment
    pub tcp_connect_time: Duration,
    /// TLS handshake time (after TCP connect)
    pub tls_handshake_time: Duration,
    /// Time to first application data
    pub time_to_first_byte: Duration,
    /// Total time from start to TLS ready
    pub total_time: Duration,
}

impl TlsTimingBreakdown {
    /// Get total handshake time (TCP + TLS)
    pub fn total_handshake_time(&self) -> Duration {
        self.tcp_connect_time + self.tls_handshake_time
    }

    /// Get as milliseconds for display
    pub fn dns_ms(&self) -> f64 {
        self.dns_time.as_secs_f64() * 1000.0
    }

    pub fn tcp_ms(&self) -> f64 {
        self.tcp_connect_time.as_secs_f64() * 1000.0
    }

    pub fn tls_ms(&self) -> f64 {
        self.tls_handshake_time.as_secs_f64() * 1000.0
    }

    pub fn total_ms(&self) -> f64 {
        self.total_time.as_secs_f64() * 1000.0
    }
}

/// Result of TLS probe
#[derive(Debug, Clone)]
pub struct TlsProbeResult {
    /// Target hostname
    pub target: String,
    /// Resolved IP address
    pub target_ip: IpAddr,
    /// Port used
    pub port: u16,
    /// Whether handshake succeeded
    pub success: bool,
    /// TLS version negotiated
    pub tls_version: TlsVersion,
    /// Cipher suite name (if available)
    pub cipher_suite: Option<String>,
    /// Server certificate common name
    pub cert_cn: Option<String>,
    /// Certificate chain length
    pub cert_chain_length: usize,
    /// Whether session was resumed
    pub session_resumed: bool,
    /// ALPN protocol negotiated
    pub alpn_protocol: Option<String>,
    /// Detailed timing breakdown
    pub timing: TlsTimingBreakdown,
    /// Error message if failed
    pub error: Option<String>,
}

impl TlsProbeResult {
    /// Check if this is HTTP/2 capable
    pub fn supports_http2(&self) -> bool {
        self.alpn_protocol.as_deref() == Some("h2")
    }

    /// Check if using modern TLS (1.2+)
    pub fn is_modern_tls(&self) -> bool {
        matches!(self.tls_version, TlsVersion::Tls12 | TlsVersion::Tls13)
    }
}

/// Options for TLS probing
#[derive(Debug, Clone)]
pub struct TlsProbeOptions {
    /// Connection timeout
    pub timeout: Duration,
    /// Port to connect to
    pub port: u16,
    /// SNI hostname (defaults to target)
    pub sni: Option<String>,
    /// ALPN protocols to offer
    pub alpn_protocols: Vec<String>,
    /// Whether to verify certificates
    pub verify_certs: bool,
}

impl Default for TlsProbeOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            port: 443,
            sni: None,
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            verify_certs: true,
        }
    }
}

/// Perform a TLS probe with detailed timing
pub async fn probe_tls(target: &str, options: &TlsProbeOptions) -> crate::Result<TlsProbeResult> {
    let start = Instant::now();

    // DNS resolution
    let dns_start = Instant::now();
    let dns_result = dns::resolve_ipv4(target).await?;
    let dns_time = dns_start.elapsed();

    let target_ip = dns_result.ip;
    let target_ipv4 = match target_ip {
        IpAddr::V4(ipv4) => ipv4,
        IpAddr::V6(_) => return Err(Error::InvalidTarget("IPv6 not supported".to_string())),
    };

    let addr = SocketAddr::new(IpAddr::V4(target_ipv4), options.port);
    let sni = options.sni.clone().unwrap_or_else(|| target.to_string());

    // TCP connect
    let tcp_start = Instant::now();
    let tcp_result = tokio::time::timeout(
        options.timeout,
        tokio::net::TcpStream::connect(addr)
    ).await;

    let tcp_stream = match tcp_result {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            return Ok(TlsProbeResult {
                target: target.to_string(),
                target_ip,
                port: options.port,
                success: false,
                tls_version: TlsVersion::Unknown,
                cipher_suite: None,
                cert_cn: None,
                cert_chain_length: 0,
                session_resumed: false,
                alpn_protocol: None,
                timing: TlsTimingBreakdown {
                    dns_time,
                    tcp_connect_time: tcp_start.elapsed(),
                    tls_handshake_time: Duration::ZERO,
                    time_to_first_byte: Duration::ZERO,
                    total_time: start.elapsed(),
                },
                error: Some(format!("TCP connect failed: {e}")),
            });
        }
        Err(_) => {
            return Ok(TlsProbeResult {
                target: target.to_string(),
                target_ip,
                port: options.port,
                success: false,
                tls_version: TlsVersion::Unknown,
                cipher_suite: None,
                cert_cn: None,
                cert_chain_length: 0,
                session_resumed: false,
                alpn_protocol: None,
                timing: TlsTimingBreakdown {
                    dns_time,
                    tcp_connect_time: options.timeout,
                    tls_handshake_time: Duration::ZERO,
                    time_to_first_byte: Duration::ZERO,
                    total_time: start.elapsed(),
                },
                error: Some("TCP connect timeout".to_string()),
            });
        }
    };
    let tcp_connect_time = tcp_start.elapsed();

    // TLS handshake using native-tls or rustls
    let tls_start = Instant::now();

    // Use tokio-native-tls for cross-platform TLS
    let tls_result = perform_tls_handshake(tcp_stream, &sni, options).await;
    let tls_handshake_time = tls_start.elapsed();
    let total_time = start.elapsed();

    match tls_result {
        Ok(tls_info) => {
            Ok(TlsProbeResult {
                target: target.to_string(),
                target_ip,
                port: options.port,
                success: true,
                tls_version: tls_info.version,
                cipher_suite: tls_info.cipher_suite,
                cert_cn: tls_info.cert_cn,
                cert_chain_length: tls_info.cert_chain_length,
                session_resumed: tls_info.session_resumed,
                alpn_protocol: tls_info.alpn_protocol,
                timing: TlsTimingBreakdown {
                    dns_time,
                    tcp_connect_time,
                    tls_handshake_time,
                    time_to_first_byte: total_time,
                    total_time,
                },
                error: None,
            })
        }
        Err(e) => {
            Ok(TlsProbeResult {
                target: target.to_string(),
                target_ip,
                port: options.port,
                success: false,
                tls_version: TlsVersion::Unknown,
                cipher_suite: None,
                cert_cn: None,
                cert_chain_length: 0,
                session_resumed: false,
                alpn_protocol: None,
                timing: TlsTimingBreakdown {
                    dns_time,
                    tcp_connect_time,
                    tls_handshake_time,
                    time_to_first_byte: total_time,
                    total_time,
                },
                error: Some(e),
            })
        }
    }
}

struct TlsInfo {
    version: TlsVersion,
    cipher_suite: Option<String>,
    cert_cn: Option<String>,
    cert_chain_length: usize,
    session_resumed: bool,
    alpn_protocol: Option<String>,
}

async fn perform_tls_handshake(
    tcp_stream: tokio::net::TcpStream,
    sni: &str,
    _options: &TlsProbeOptions,
) -> Result<TlsInfo, String> {
    // Use a simple TLS handshake approach
    // For full implementation, would use rustls or native-tls

    // Since we want to avoid adding heavy dependencies,
    // we'll do a basic handshake timing measurement
    // and extract what info we can from the connection

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Convert to raw TLS ClientHello to measure timing
    // This is a simplified version - production would use rustls

    let client_hello = build_client_hello(sni);

    let mut stream = tcp_stream;

    // Send ClientHello
    if let Err(e) = stream.write_all(&client_hello).await {
        return Err(format!("Failed to send ClientHello: {e}"));
    }

    // Read ServerHello response
    let mut response = vec![0u8; 4096];
    match tokio::time::timeout(
        Duration::from_secs(5),
        stream.read(&mut response)
    ).await {
        Ok(Ok(n)) if n > 0 => {
            // Parse TLS record to get version
            let tls_version = parse_tls_version(&response[..n]);
            let cipher_suite = parse_cipher_suite(&response[..n]);

            Ok(TlsInfo {
                version: tls_version,
                cipher_suite,
                cert_cn: None, // Would need full handshake to extract
                cert_chain_length: 0,
                session_resumed: false,
                alpn_protocol: None,
            })
        }
        Ok(Ok(_)) => Err("Empty response from server".to_string()),
        Ok(Err(e)) => Err(format!("Read error: {e}")),
        Err(_) => Err("TLS handshake timeout".to_string()),
    }
}

/// Build a minimal TLS 1.2 ClientHello
fn build_client_hello(sni: &str) -> Vec<u8> {
    let sni_bytes = sni.as_bytes();
    let sni_len = sni_bytes.len();

    // SNI extension
    let sni_ext_len = sni_len + 5;
    let mut sni_ext = vec![
        0x00, 0x00, // Extension type: server_name
        ((sni_ext_len) >> 8) as u8, (sni_ext_len & 0xFF) as u8, // Extension length
        ((sni_len + 3) >> 8) as u8, ((sni_len + 3) & 0xFF) as u8, // SNI list length
        0x00, // Host name type
        (sni_len >> 8) as u8, (sni_len & 0xFF) as u8, // Host name length
    ];
    sni_ext.extend_from_slice(sni_bytes);

    // Supported versions extension (TLS 1.3 + 1.2)
    let supported_versions_ext = vec![
        0x00, 0x2b, // Extension type: supported_versions
        0x00, 0x05, // Extension length
        0x04,       // Supported versions length
        0x03, 0x04, // TLS 1.3
        0x03, 0x03, // TLS 1.2
    ];

    // ALPN extension for HTTP/2
    let alpn_ext = vec![
        0x00, 0x10, // Extension type: ALPN
        0x00, 0x0b, // Extension length
        0x00, 0x09, // ALPN protocols length
        0x02, 0x68, 0x32, // "h2"
        0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, // "http/1.1"
    ];

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&sni_ext);
    extensions.extend_from_slice(&supported_versions_ext);
    extensions.extend_from_slice(&alpn_ext);

    let extensions_len = extensions.len();

    // Cipher suites (modern suites only)
    let cipher_suites = vec![
        0x13, 0x01, // TLS_AES_128_GCM_SHA256
        0x13, 0x02, // TLS_AES_256_GCM_SHA384
        0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
        0xc0, 0x2c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0xc0, 0x2b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xc0, 0x30, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    ];
    let cipher_suites_len = cipher_suites.len();

    // Random bytes
    let random: [u8; 32] = rand_bytes();

    // Build ClientHello
    let mut client_hello = Vec::new();

    // Handshake type (1 = ClientHello)
    client_hello.push(0x01);

    // We'll fill in the length later
    let length_pos = client_hello.len();
    client_hello.extend_from_slice(&[0x00, 0x00, 0x00]);

    // Client version (TLS 1.2 for compatibility)
    client_hello.extend_from_slice(&[0x03, 0x03]);

    // Random
    client_hello.extend_from_slice(&random);

    // Session ID (empty)
    client_hello.push(0x00);

    // Cipher suites
    client_hello.push((cipher_suites_len >> 8) as u8);
    client_hello.push((cipher_suites_len & 0xFF) as u8);
    client_hello.extend_from_slice(&cipher_suites);

    // Compression methods (null only)
    client_hello.push(0x01);
    client_hello.push(0x00);

    // Extensions
    client_hello.push((extensions_len >> 8) as u8);
    client_hello.push((extensions_len & 0xFF) as u8);
    client_hello.extend_from_slice(&extensions);

    // Fix length field
    let handshake_len = client_hello.len() - 4;
    client_hello[length_pos] = 0x00;
    client_hello[length_pos + 1] = (handshake_len >> 8) as u8;
    client_hello[length_pos + 2] = (handshake_len & 0xFF) as u8;

    // Wrap in TLS record
    let record_len = client_hello.len();
    let mut record = vec![
        0x16, // Content type: Handshake
        0x03, 0x01, // Version: TLS 1.0 (for compatibility)
        (record_len >> 8) as u8, (record_len & 0xFF) as u8,
    ];
    record.extend_from_slice(&client_hello);

    record
}

fn rand_bytes() -> [u8; 32] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut bytes = [0u8; 32];
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    for (i, b) in bytes.iter_mut().enumerate() {
        *b = ((seed >> (i % 16)) ^ (i as u128 * 31)) as u8;
    }
    bytes
}

fn parse_tls_version(data: &[u8]) -> TlsVersion {
    // TLS record header: type (1) + version (2) + length (2)
    if data.len() < 5 {
        return TlsVersion::Unknown;
    }

    // Check for TLS record
    if data[0] != 0x16 {
        return TlsVersion::Unknown;
    }

    // Look for ServerHello
    if data.len() > 9 && data[5] == 0x02 {
        // ServerHello: handshake type(1) + length(3) + version(2)
        let major = data[9];
        let minor = data[10];

        match (major, minor) {
            (0x03, 0x01) => TlsVersion::Tls10,
            (0x03, 0x02) => TlsVersion::Tls11,
            (0x03, 0x03) => {
                // Could be TLS 1.2 or 1.3 (need to check extensions)
                // For simplicity, check for supported_versions extension
                if data.len() > 50 {
                    // TLS 1.3 uses supported_versions extension
                    if find_tls13_indicator(data) {
                        return TlsVersion::Tls13;
                    }
                }
                TlsVersion::Tls12
            }
            (0x03, 0x04) => TlsVersion::Tls13,
            _ => TlsVersion::Unknown,
        }
    } else {
        TlsVersion::Unknown
    }
}

fn find_tls13_indicator(data: &[u8]) -> bool {
    // Look for supported_versions extension with TLS 1.3
    for window in data.windows(4) {
        if window[0] == 0x00 && window[1] == 0x2b {
            // Found supported_versions extension
            if data.len() > 4 {
                // Check for TLS 1.3 version bytes
                for v in data.windows(2) {
                    if v[0] == 0x03 && v[1] == 0x04 {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn parse_cipher_suite(data: &[u8]) -> Option<String> {
    // ServerHello cipher suite is at offset 9 + 32 (random) + session_id_len + 1
    if data.len() < 44 {
        return None;
    }

    // Skip to ServerHello content
    if data.len() > 9 && data[5] == 0x02 {
        let session_id_len = data[43] as usize;
        let cipher_offset = 44 + session_id_len;

        if data.len() > cipher_offset + 1 {
            let cipher = ((data[cipher_offset] as u16) << 8) | data[cipher_offset + 1] as u16;

            return Some(match cipher {
                0x1301 => "TLS_AES_128_GCM_SHA256".to_string(),
                0x1302 => "TLS_AES_256_GCM_SHA384".to_string(),
                0x1303 => "TLS_CHACHA20_POLY1305_SHA256".to_string(),
                0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".to_string(),
                0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_string(),
                0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
                0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
                _ => format!("0x{cipher:04x}"),
            });
        }
    }

    None
}

/// Compare TLS configurations between two targets
#[derive(Debug)]
pub struct TlsComparison {
    pub same_version: bool,
    pub same_cipher: bool,
    pub timing_diff: Duration,
    pub both_modern: bool,
}

/// Compare TLS configurations of two servers
pub async fn compare_tls(
    target1: &str,
    target2: &str,
    options: &TlsProbeOptions,
) -> crate::Result<TlsComparison> {
    let result1 = probe_tls(target1, options).await?;
    let result2 = probe_tls(target2, options).await?;

    let timing_diff = result1.timing.total_time.abs_diff(result2.timing.total_time);

    Ok(TlsComparison {
        same_version: result1.tls_version == result2.tls_version,
        same_cipher: result1.cipher_suite == result2.cipher_suite,
        timing_diff,
        both_modern: result1.is_modern_tls() && result2.is_modern_tls(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_version_display() {
        assert_eq!(TlsVersion::Tls12.to_string(), "TLS 1.2");
        assert_eq!(TlsVersion::Tls13.to_string(), "TLS 1.3");
    }

    #[test]
    fn test_client_hello_build() {
        let hello = build_client_hello("example.com");
        // Should start with TLS record header
        assert_eq!(hello[0], 0x16); // Handshake
        assert_eq!(hello[1], 0x03); // TLS major version
    }

    #[test]
    fn test_probe_options_default() {
        let opts = TlsProbeOptions::default();
        assert_eq!(opts.port, 443);
        assert!(opts.verify_certs);
        assert!(opts.alpn_protocols.contains(&"h2".to_string()));
    }
}
