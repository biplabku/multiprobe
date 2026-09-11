//! Error types for multiprobe

use std::io;
use thiserror::Error;

/// Main error type for multiprobe operations
#[derive(Error, Debug)]
pub enum Error {
    /// DNS resolution failed
    #[error("DNS resolution failed for '{host}': {message}")]
    DnsResolution {
        host: String,
        message: String,
    },

    /// Socket creation failed
    #[error("Failed to create socket: {0}")]
    SocketCreation(#[source] io::Error),

    /// Connection failed
    #[error("Connection failed to {target}: {message}")]
    ConnectionFailed {
        target: String,
        message: String,
    },

    /// Operation timed out
    #[error("Operation timed out after {timeout_ms}ms")]
    Timeout {
        timeout_ms: u64,
    },

    /// ICMP-specific error
    #[error("ICMP error: {0}")]
    Icmp(String),

    /// Permission denied (likely needs CAP_NET_RAW)
    #[error("Permission denied - raw sockets require elevated privileges (CAP_NET_RAW on Linux)")]
    PermissionDenied,

    /// Invalid target specification
    #[error("Invalid target: {0}")]
    InvalidTarget(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Host unreachable
    #[error("Host unreachable: {host}")]
    HostUnreachable {
        host: String,
    },

    /// Network unreachable
    #[error("Network unreachable")]
    NetworkUnreachable,

    /// Connection refused
    #[error("Connection refused by {host}:{port}")]
    ConnectionRefused {
        host: String,
        port: u16,
    },

    /// DNS lookup error (for ASN lookups)
    #[error("DNS lookup error: {0}")]
    Dns(String),
}

impl Error {
    /// Returns true if this error indicates the probe reached the target
    /// but was refused (useful for port scanning / firewall detection)
    pub fn is_refused(&self) -> bool {
        matches!(self, Error::ConnectionRefused { .. })
    }

    /// Returns true if this error indicates a timeout
    pub fn is_timeout(&self) -> bool {
        matches!(self, Error::Timeout { .. })
    }

    /// Returns true if this is a permission error
    pub fn is_permission_denied(&self) -> bool {
        matches!(self, Error::PermissionDenied)
    }
}
