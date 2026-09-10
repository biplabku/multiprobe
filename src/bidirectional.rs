//! Bidirectional path probing for detecting reverse-path asymmetry
//!
//! This module provides tools to measure both forward and reverse network paths,
//! which is essential for diagnosing ECMP asymmetry where packets take different
//! paths in each direction.
//!
//! # Architecture
//!
//! ```text
//! [Client]  ──forward probes──>  [Server]
//!           <──reverse probes──
//! ```
//!
//! The server echoes probes with embedded timestamps, allowing the client
//! to measure latency in both directions independently.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::dns;
use crate::error::Error;

/// Default port for bidirectional probing
pub const DEFAULT_PORT: u16 = 33435;

/// Magic bytes to identify multiprobe bidirectional packets
const MAGIC: [u8; 4] = [0x4D, 0x50, 0x42, 0x44]; // "MPBD"

/// Protocol version
const VERSION: u8 = 1;

/// Message types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Probe = 1,
    Echo = 2,
    Ping = 3,
    Pong = 4,
}

impl TryFrom<u8> for MessageType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(MessageType::Probe),
            2 => Ok(MessageType::Echo),
            3 => Ok(MessageType::Ping),
            4 => Ok(MessageType::Pong),
            _ => Err(()),
        }
    }
}

/// Probe message sent from client to server
#[derive(Debug, Clone)]
struct ProbeMessage {
    sequence: u32,
    client_send_time: u64,
}

impl ProbeMessage {
    fn new(sequence: u32) -> Self {
        let client_send_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        Self {
            sequence,
            client_send_time,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(17);
        buf.extend_from_slice(&MAGIC);
        buf.push(VERSION);
        buf.push(MessageType::Probe as u8);
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&self.client_send_time.to_be_bytes());
        buf
    }

    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 18 || data[0..4] != MAGIC || data[4] != VERSION {
            return None;
        }

        let msg_type = MessageType::try_from(data[5]).ok()?;
        if msg_type != MessageType::Probe {
            return None;
        }

        let sequence = u32::from_be_bytes([data[6], data[7], data[8], data[9]]);
        let client_send_time = u64::from_be_bytes([
            data[10], data[11], data[12], data[13],
            data[14], data[15], data[16], data[17],
        ]);

        Some(Self { sequence, client_send_time })
    }
}

/// Echo message sent from server back to client
#[derive(Debug, Clone)]
struct EchoMessage {
    sequence: u32,
    client_send_time: u64,
    server_recv_time: u64,
    server_send_time: u64,
}

impl EchoMessage {
    fn from_probe(probe: &ProbeMessage) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        Self {
            sequence: probe.sequence,
            client_send_time: probe.client_send_time,
            server_recv_time: now,
            server_send_time: now,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(34);
        buf.extend_from_slice(&MAGIC);
        buf.push(VERSION);
        buf.push(MessageType::Echo as u8);
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&self.client_send_time.to_be_bytes());
        buf.extend_from_slice(&self.server_recv_time.to_be_bytes());
        buf.extend_from_slice(&self.server_send_time.to_be_bytes());
        buf
    }

    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 34 || data[0..4] != MAGIC || data[4] != VERSION {
            return None;
        }

        let msg_type = MessageType::try_from(data[5]).ok()?;
        if msg_type != MessageType::Echo {
            return None;
        }

        let sequence = u32::from_be_bytes([data[6], data[7], data[8], data[9]]);
        let client_send_time = u64::from_be_bytes([
            data[10], data[11], data[12], data[13],
            data[14], data[15], data[16], data[17],
        ]);
        let server_recv_time = u64::from_be_bytes([
            data[18], data[19], data[20], data[21],
            data[22], data[23], data[24], data[25],
        ]);
        let server_send_time = u64::from_be_bytes([
            data[26], data[27], data[28], data[29],
            data[30], data[31], data[32], data[33],
        ]);

        Some(Self {
            sequence,
            client_send_time,
            server_recv_time,
            server_send_time,
        })
    }
}

/// Statistics for one direction of the path
#[derive(Debug, Clone)]
pub struct DirectionStats {
    /// Number of probes sent
    pub sent: u32,
    /// Number of responses received
    pub received: u32,
    /// Minimum latency in this direction
    pub min_ms: f64,
    /// Maximum latency in this direction
    pub max_ms: f64,
    /// Mean latency in this direction
    pub mean_ms: f64,
    /// Jitter (mean absolute deviation)
    pub jitter_ms: f64,
    /// Individual samples (microseconds)
    samples: Vec<u64>,
}

impl DirectionStats {
    fn new() -> Self {
        Self {
            sent: 0,
            received: 0,
            min_ms: f64::MAX,
            max_ms: 0.0,
            mean_ms: 0.0,
            jitter_ms: 0.0,
            samples: Vec::new(),
        }
    }

    fn add_sample(&mut self, latency_us: u64) {
        self.received += 1;
        self.samples.push(latency_us);

        let latency_ms = latency_us as f64 / 1000.0;

        if latency_ms < self.min_ms {
            self.min_ms = latency_ms;
        }
        if latency_ms > self.max_ms {
            self.max_ms = latency_ms;
        }
    }

    fn finalize(&mut self) {
        if self.samples.is_empty() {
            self.min_ms = 0.0;
            return;
        }

        let sum: u64 = self.samples.iter().sum();
        self.mean_ms = (sum as f64 / self.samples.len() as f64) / 1000.0;

        if self.samples.len() > 1 {
            let mut jitter_sum = 0.0;
            for i in 1..self.samples.len() {
                jitter_sum += (self.samples[i] as f64 - self.samples[i-1] as f64).abs();
            }
            self.jitter_ms = (jitter_sum / (self.samples.len() - 1) as f64) / 1000.0;
        }
    }

    /// Calculate packet loss percentage
    pub fn loss_percent(&self) -> f64 {
        if self.sent == 0 {
            0.0
        } else {
            ((self.sent - self.received) as f64 / self.sent as f64) * 100.0
        }
    }
}

/// Result of bidirectional path probing
#[derive(Debug, Clone)]
pub struct BidirectionalResult {
    /// Target hostname
    pub target: String,
    /// Resolved IP address
    pub target_ip: IpAddr,
    /// Server port
    pub port: u16,
    /// Forward path statistics (client → server)
    pub forward: DirectionStats,
    /// Reverse path statistics (server → client)
    pub reverse: DirectionStats,
    /// Round-trip statistics (client → server → client)
    pub round_trip: DirectionStats,
    /// Asymmetry score (0.0 = symmetric, 1.0 = highly asymmetric)
    pub asymmetry_score: f64,
    /// Whether significant asymmetry was detected
    pub asymmetric: bool,
    /// Total probes attempted
    pub probe_count: u32,
    /// Test duration
    pub duration: Duration,
}

impl BidirectionalResult {
    /// Interpret the asymmetry
    pub fn interpretation(&self) -> &'static str {
        if self.asymmetry_score < 0.1 {
            "Symmetric path"
        } else if self.asymmetry_score < 0.3 {
            "Slight asymmetry"
        } else if self.asymmetry_score < 0.5 {
            "Moderate asymmetry"
        } else {
            "Significant asymmetry - likely different ECMP paths"
        }
    }
}

/// Options for bidirectional probing
#[derive(Debug, Clone)]
pub struct BidirectionalOptions {
    /// Port to connect to (default: 33435)
    pub port: u16,
    /// Number of probes to send
    pub probe_count: u32,
    /// Interval between probes
    pub interval: Duration,
    /// Timeout for each probe
    pub timeout: Duration,
}

impl Default for BidirectionalOptions {
    fn default() -> Self {
        Self {
            port: DEFAULT_PORT,
            probe_count: 10,
            interval: Duration::from_millis(100),
            timeout: Duration::from_secs(5),
        }
    }
}

/// Server for bidirectional probing
pub struct BidirectionalServer {
    listener: TcpListener,
    running: Arc<AtomicBool>,
    probes_handled: Arc<AtomicU64>,
}

impl BidirectionalServer {
    /// Create a new bidirectional probe server
    pub async fn bind(addr: &str) -> crate::Result<Self> {
        let listener = TcpListener::bind(addr).await
            .map_err(Error::SocketCreation)?;

        Ok(Self {
            listener,
            running: Arc::new(AtomicBool::new(false)),
            probes_handled: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Get the local address the server is bound to
    pub fn local_addr(&self) -> crate::Result<SocketAddr> {
        self.listener.local_addr()
            .map_err(Error::SocketCreation)
    }

    /// Get the number of probes handled
    pub fn probes_handled(&self) -> u64 {
        self.probes_handled.load(Ordering::Relaxed)
    }

    /// Check if the server is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Stop the server
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Run the server, handling incoming connections
    pub async fn run(&self) -> crate::Result<()> {
        self.running.store(true, Ordering::Relaxed);

        while self.running.load(Ordering::Relaxed) {
            let accept_result = timeout(
                Duration::from_millis(100),
                self.listener.accept()
            ).await;

            match accept_result {
                Ok(Ok((stream, _addr))) => {
                    let probes_handled = self.probes_handled.clone();
                    tokio::spawn(async move {
                        let _ = Self::handle_connection(stream, probes_handled).await;
                    });
                }
                Ok(Err(e)) => {
                    if self.running.load(Ordering::Relaxed) {
                        return Err(Error::ConnectionFailed {
                            target: "server".to_string(),
                            message: e.to_string(),
                        });
                    }
                }
                Err(_) => {
                    // Timeout - check if we should keep running
                    continue;
                }
            }
        }

        Ok(())
    }

    async fn handle_connection(
        mut stream: TcpStream,
        probes_handled: Arc<AtomicU64>,
    ) -> crate::Result<()> {
        let mut buf = [0u8; 64];

        loop {
            match stream.read(&mut buf).await {
                Ok(0) => break, // Connection closed
                Ok(n) => {
                    if let Some(probe) = ProbeMessage::from_bytes(&buf[..n]) {
                        let echo = EchoMessage::from_probe(&probe);
                        let echo_bytes = echo.to_bytes();

                        if stream.write_all(&echo_bytes).await.is_ok() {
                            probes_handled.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                Err(_) => break,
            }
        }

        Ok(())
    }
}

/// Perform bidirectional probing to a target running a multiprobe server
pub async fn probe_bidirectional(
    target: &str,
    options: &BidirectionalOptions,
) -> crate::Result<BidirectionalResult> {
    let start = Instant::now();

    // DNS resolution
    let dns_result = dns::resolve_ipv4(target).await?;
    let target_ip = dns_result.ip;
    let addr = SocketAddr::new(target_ip, options.port);

    // Connect to server
    let mut stream = timeout(options.timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| Error::Timeout { timeout_ms: options.timeout.as_millis() as u64 })?
        .map_err(|e| Error::ConnectionFailed {
            target: target.to_string(),
            message: e.to_string(),
        })?;

    let mut forward = DirectionStats::new();
    let mut reverse = DirectionStats::new();
    let mut round_trip = DirectionStats::new();

    let mut buf = [0u8; 64];

    for seq in 0..options.probe_count {
        forward.sent += 1;
        reverse.sent += 1;
        round_trip.sent += 1;

        let probe = ProbeMessage::new(seq);
        let probe_bytes = probe.to_bytes();
        let send_time = Instant::now();

        // Send probe
        if stream.write_all(&probe_bytes).await.is_err() {
            continue;
        }

        // Wait for echo
        let read_result = timeout(options.timeout, stream.read(&mut buf)).await;
        let recv_time = Instant::now();

        match read_result {
            Ok(Ok(n)) if n > 0 => {
                if let Some(echo) = EchoMessage::from_bytes(&buf[..n]) {
                    let client_recv_time = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_micros() as u64;

                    // Forward latency: client_send → server_recv
                    let forward_latency = echo.server_recv_time.saturating_sub(echo.client_send_time);
                    forward.add_sample(forward_latency);

                    // Reverse latency: server_send → client_recv
                    let reverse_latency = client_recv_time.saturating_sub(echo.server_send_time);
                    reverse.add_sample(reverse_latency);

                    // Round-trip measured locally
                    let rtt = recv_time.duration_since(send_time).as_micros() as u64;
                    round_trip.add_sample(rtt);
                }
            }
            _ => {
                // Timeout or error - packet lost
            }
        }

        // Wait for interval
        if seq < options.probe_count - 1 {
            tokio::time::sleep(options.interval).await;
        }
    }

    // Finalize statistics
    forward.finalize();
    reverse.finalize();
    round_trip.finalize();

    // Calculate asymmetry score
    let asymmetry_score = if forward.received > 0 && reverse.received > 0 {
        let diff = (forward.mean_ms - reverse.mean_ms).abs();
        let avg = (forward.mean_ms + reverse.mean_ms) / 2.0;
        if avg > 0.0 {
            (diff / avg).min(1.0)
        } else {
            0.0
        }
    } else {
        0.0
    };

    let duration = start.elapsed();

    Ok(BidirectionalResult {
        target: target.to_string(),
        target_ip,
        port: options.port,
        forward,
        reverse,
        round_trip,
        asymmetry_score,
        asymmetric: asymmetry_score > 0.3,
        probe_count: options.probe_count,
        duration,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_probe_message_serialization() {
        let probe = ProbeMessage::new(42);
        let bytes = probe.to_bytes();

        assert_eq!(&bytes[0..4], &MAGIC);
        assert_eq!(bytes[4], VERSION);
        assert_eq!(bytes[5], MessageType::Probe as u8);

        let parsed = ProbeMessage::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.sequence, 42);
        assert_eq!(parsed.client_send_time, probe.client_send_time);
    }

    #[test]
    fn test_echo_message_serialization() {
        let probe = ProbeMessage::new(123);
        let echo = EchoMessage::from_probe(&probe);
        let bytes = echo.to_bytes();

        assert_eq!(&bytes[0..4], &MAGIC);
        assert_eq!(bytes[4], VERSION);
        assert_eq!(bytes[5], MessageType::Echo as u8);

        let parsed = EchoMessage::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.sequence, 123);
        assert_eq!(parsed.client_send_time, probe.client_send_time);
    }

    #[test]
    fn test_invalid_message() {
        let invalid = [0u8; 10];
        assert!(ProbeMessage::from_bytes(&invalid).is_none());
        assert!(EchoMessage::from_bytes(&invalid).is_none());
    }

    #[test]
    fn test_direction_stats() {
        let mut stats = DirectionStats::new();

        stats.sent = 5;
        stats.add_sample(10_000); // 10ms
        stats.add_sample(15_000); // 15ms
        stats.add_sample(12_000); // 12ms

        stats.finalize();

        assert_eq!(stats.received, 3);
        assert!((stats.min_ms - 10.0).abs() < 0.01);
        assert!((stats.max_ms - 15.0).abs() < 0.01);
        assert!((stats.mean_ms - 12.33).abs() < 0.1);
        assert!(stats.jitter_ms > 0.0);
        assert!((stats.loss_percent() - 40.0).abs() < 0.01);
    }

    #[test]
    fn test_direction_stats_empty() {
        let mut stats = DirectionStats::new();
        stats.sent = 3;
        stats.finalize();

        assert_eq!(stats.received, 0);
        assert_eq!(stats.min_ms, 0.0);
        assert_eq!(stats.mean_ms, 0.0);
        assert!((stats.loss_percent() - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_direction_stats_single_sample() {
        let mut stats = DirectionStats::new();
        stats.sent = 1;
        stats.add_sample(5_000);
        stats.finalize();

        assert_eq!(stats.received, 1);
        assert!((stats.min_ms - 5.0).abs() < 0.01);
        assert!((stats.max_ms - 5.0).abs() < 0.01);
        assert!((stats.mean_ms - 5.0).abs() < 0.01);
        assert_eq!(stats.jitter_ms, 0.0);
    }

    #[test]
    fn test_asymmetry_interpretation() {
        let result = BidirectionalResult {
            target: "test".to_string(),
            target_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: DEFAULT_PORT,
            forward: DirectionStats::new(),
            reverse: DirectionStats::new(),
            round_trip: DirectionStats::new(),
            asymmetry_score: 0.05,
            asymmetric: false,
            probe_count: 10,
            duration: Duration::from_secs(1),
        };

        assert_eq!(result.interpretation(), "Symmetric path");

        let result2 = BidirectionalResult {
            asymmetry_score: 0.6,
            asymmetric: true,
            ..result.clone()
        };

        assert!(result2.interpretation().contains("Significant"));
    }

    #[test]
    fn test_options_default() {
        let opts = BidirectionalOptions::default();

        assert_eq!(opts.port, DEFAULT_PORT);
        assert_eq!(opts.probe_count, 10);
        assert_eq!(opts.interval, Duration::from_millis(100));
        assert_eq!(opts.timeout, Duration::from_secs(5));
    }

    #[tokio::test]
    async fn test_server_client_integration() {
        // Start server on random port
        let server = BidirectionalServer::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let port = addr.port();

        // Run server in background
        let server_running = server.running.clone();
        let server_handle = tokio::spawn(async move {
            let _ = server.run().await;
        });

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Run client
        let options = BidirectionalOptions {
            port,
            probe_count: 5,
            interval: Duration::from_millis(10),
            timeout: Duration::from_secs(2),
        };

        let result = probe_bidirectional("127.0.0.1", &options).await.unwrap();

        assert_eq!(result.target, "127.0.0.1");
        assert_eq!(result.port, port);
        assert_eq!(result.probe_count, 5);
        assert!(result.forward.received > 0);
        assert!(result.reverse.received > 0);
        assert!(result.round_trip.received > 0);

        // Localhost latencies are very small (sub-millisecond), so percentage-based
        // asymmetry can be high due to timing jitter. Just verify we got valid data.
        assert!(result.round_trip.mean_ms < 50.0); // Should be fast on localhost
        // Note: We don't assert on asymmetry_score for localhost since tiny latencies
        // can produce high percentage variations

        // Stop server
        server_running.store(false, Ordering::Relaxed);
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_server_handles_multiple_probes() {
        let server = BidirectionalServer::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let port = addr.port();
        let probes_counter = server.probes_handled.clone();
        let server_running = server.running.clone();

        let server_handle = tokio::spawn(async move {
            let _ = server.run().await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let options = BidirectionalOptions {
            port,
            probe_count: 20,
            interval: Duration::from_millis(5),
            timeout: Duration::from_secs(2),
        };

        let result = probe_bidirectional("127.0.0.1", &options).await.unwrap();

        assert!(result.round_trip.received >= 15); // Allow some loss
        assert!(probes_counter.load(Ordering::Relaxed) >= 15);

        server_running.store(false, Ordering::Relaxed);
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_connection_to_nonexistent_server() {
        let options = BidirectionalOptions {
            port: 59999, // Unlikely to be in use
            probe_count: 1,
            timeout: Duration::from_millis(500),
            ..Default::default()
        };

        let result = probe_bidirectional("127.0.0.1", &options).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_server_bind_address() {
        let server = BidirectionalServer::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();

        assert_eq!(addr.ip(), std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(addr.port() > 0);
    }

    #[test]
    fn test_message_type_conversion() {
        assert_eq!(MessageType::try_from(1), Ok(MessageType::Probe));
        assert_eq!(MessageType::try_from(2), Ok(MessageType::Echo));
        assert_eq!(MessageType::try_from(3), Ok(MessageType::Ping));
        assert_eq!(MessageType::try_from(4), Ok(MessageType::Pong));
        assert!(MessageType::try_from(99).is_err());
    }

    #[test]
    fn test_probe_sequence_numbers() {
        for seq in [0, 1, 100, u32::MAX] {
            let probe = ProbeMessage {
                sequence: seq,
                client_send_time: 12345,
            };
            let bytes = probe.to_bytes();
            let parsed = ProbeMessage::from_bytes(&bytes).unwrap();
            assert_eq!(parsed.sequence, seq);
        }
    }

    #[test]
    fn test_timestamp_preservation() {
        let probe = ProbeMessage {
            sequence: 1,
            client_send_time: 1234567890123456,
        };

        let echo = EchoMessage::from_probe(&probe);
        assert_eq!(echo.client_send_time, probe.client_send_time);
        assert!(echo.server_recv_time > 0);
        assert!(echo.server_send_time >= echo.server_recv_time);

        let bytes = echo.to_bytes();
        let parsed = EchoMessage::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.client_send_time, echo.client_send_time);
        assert_eq!(parsed.server_recv_time, echo.server_recv_time);
        assert_eq!(parsed.server_send_time, echo.server_send_time);
    }
}
