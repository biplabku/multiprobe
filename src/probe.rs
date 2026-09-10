//! High-level probe API

use std::time::Duration;

use crate::classifier::Classifier;
use crate::error::Error;
use crate::traceroute::{TracerouteOptions, TracerouteResult};
use crate::paris::{ParisOptions, ParisTraceResult, ParisMode, FlowId};
use crate::analytics::{LatencyStats, PmtudOptions, PmtudResult, BufferbloatOptions, BufferbloatResult};
use crate::tls::{TlsProbeOptions, TlsProbeResult};
use crate::types::{MultiProbeResult, ProbeOptions, ProbeResult, Protocol};
use crate::{icmp, tcp, traceroute, udp, paris, analytics, tls};

/// Entry point for creating probes
///
/// Use the static methods to create different probe types:
/// - `Probe::icmp()` for ICMP ping
/// - `Probe::tcp()` for TCP connect probe
/// - `Probe::udp()` for UDP probe
/// - `Probe::multi()` for multi-protocol probing
pub struct Probe;

impl Probe {
    /// Create a new ICMP ping probe
    pub fn icmp(target: &str) -> IcmpProbe {
        IcmpProbe {
            target: target.to_string(),
            options: ProbeOptions::default(),
        }
    }

    /// Create a new TCP connect probe
    pub fn tcp(target: &str, port: u16) -> TcpProbe {
        TcpProbe {
            target: target.to_string(),
            port,
            options: ProbeOptions::default(),
        }
    }

    /// Create a new UDP probe
    pub fn udp(target: &str, port: u16) -> UdpProbe {
        UdpProbe {
            target: target.to_string(),
            port,
            options: ProbeOptions::default(),
        }
    }

    /// Create a multi-protocol probe builder
    pub fn multi(target: &str) -> MultiProbe {
        MultiProbe {
            target: target.to_string(),
            protocols: Vec::new(),
            options: ProbeOptions::default(),
        }
    }

    /// Create a traceroute builder
    pub fn traceroute(target: &str) -> TracerouteBuilder {
        TracerouteBuilder {
            target: target.to_string(),
            options: TracerouteOptions::default(),
        }
    }

    /// Create a Paris Traceroute builder (ECMP-aware)
    pub fn paris(target: &str) -> ParisBuilder {
        ParisBuilder {
            target: target.to_string(),
            options: ParisOptions::default(),
        }
    }

    /// Create a TLS probe builder
    pub fn tls(target: &str) -> TlsBuilder {
        TlsBuilder {
            target: target.to_string(),
            options: TlsProbeOptions::default(),
        }
    }

    /// Create a latency measurement builder
    pub fn latency(target: &str, port: u16) -> LatencyBuilder {
        LatencyBuilder {
            target: target.to_string(),
            port,
            samples: 10,
            interval: Duration::from_millis(100),
        }
    }

    /// Create a Path MTU Discovery builder
    pub fn mtu(target: &str) -> MtuBuilder {
        MtuBuilder {
            target: target.to_string(),
            options: PmtudOptions::default(),
        }
    }

    /// Create a bufferbloat detection builder
    pub fn bufferbloat(target: &str) -> BufferbloatBuilder {
        BufferbloatBuilder {
            target: target.to_string(),
            options: BufferbloatOptions::default(),
        }
    }
}

/// Traceroute builder
pub struct TracerouteBuilder {
    target: String,
    options: TracerouteOptions,
}

impl TracerouteBuilder {
    /// Set maximum number of hops
    pub fn max_hops(mut self, hops: u8) -> Self {
        self.options.max_hops = hops;
        self
    }

    /// Set timeout per hop
    pub fn timeout_per_hop(mut self, timeout: Duration) -> Self {
        self.options.timeout_per_hop = timeout;
        self
    }

    /// Set number of probes per hop
    pub fn probes_per_hop(mut self, probes: u8) -> Self {
        self.options.probes_per_hop = probes;
        self
    }

    /// Execute the traceroute
    pub async fn send(self) -> crate::Result<TracerouteResult> {
        traceroute::traceroute(&self.target, &self.options).await
    }
}

/// Paris Traceroute builder (ECMP-aware)
pub struct ParisBuilder {
    target: String,
    options: ParisOptions,
}

impl ParisBuilder {
    /// Set maximum number of hops
    pub fn max_hops(mut self, hops: u8) -> Self {
        self.options.max_hops = hops;
        self
    }

    /// Set timeout per hop
    pub fn timeout_per_hop(mut self, timeout: Duration) -> Self {
        self.options.timeout_per_hop = timeout;
        self
    }

    /// Set probe mode (UDP/ICMP/TCP)
    pub fn mode(mut self, mode: ParisMode) -> Self {
        self.options.mode = mode;
        self
    }

    /// Set flow identifier for consistent hashing
    pub fn flow_id(mut self, flow_id: FlowId) -> Self {
        self.options.flow_id = flow_id;
        self
    }

    /// Enable load balancing detection
    pub fn detect_load_balancing(mut self, detect: bool) -> Self {
        self.options.detect_load_balancing = detect;
        self
    }

    /// Execute Paris Traceroute
    pub async fn send(self) -> crate::Result<ParisTraceResult> {
        paris::paris_traceroute(&self.target, &self.options).await
    }
}

/// TLS probe builder
pub struct TlsBuilder {
    target: String,
    options: TlsProbeOptions,
}

impl TlsBuilder {
    /// Set port (default 443)
    pub fn port(mut self, port: u16) -> Self {
        self.options.port = port;
        self
    }

    /// Set SNI hostname
    pub fn sni(mut self, sni: &str) -> Self {
        self.options.sni = Some(sni.to_string());
        self
    }

    /// Set timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.options.timeout = timeout;
        self
    }

    /// Disable certificate verification
    pub fn skip_verify(mut self) -> Self {
        self.options.verify_certs = false;
        self
    }

    /// Execute TLS probe
    pub async fn send(self) -> crate::Result<TlsProbeResult> {
        tls::probe_tls(&self.target, &self.options).await
    }
}

/// Latency measurement builder
pub struct LatencyBuilder {
    target: String,
    port: u16,
    samples: usize,
    interval: Duration,
}

impl LatencyBuilder {
    /// Set number of samples
    pub fn samples(mut self, count: usize) -> Self {
        self.samples = count;
        self
    }

    /// Set interval between samples
    pub fn interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Execute latency measurement
    pub async fn send(self) -> crate::Result<LatencyStats> {
        analytics::measure_latency(&self.target, self.port, self.samples, self.interval).await
    }
}

/// Path MTU Discovery builder
pub struct MtuBuilder {
    target: String,
    options: PmtudOptions,
}

impl MtuBuilder {
    /// Set minimum MTU to test
    pub fn min_mtu(mut self, mtu: u16) -> Self {
        self.options.min_mtu = mtu;
        self
    }

    /// Set maximum MTU to test
    pub fn max_mtu(mut self, mtu: u16) -> Self {
        self.options.max_mtu = mtu;
        self
    }

    /// Set timeout per probe
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.options.timeout = timeout;
        self
    }

    /// Execute Path MTU Discovery
    pub async fn send(self) -> crate::Result<PmtudResult> {
        analytics::discover_path_mtu(&self.target, &self.options).await
    }
}

/// Bufferbloat detection builder
pub struct BufferbloatBuilder {
    target: String,
    options: BufferbloatOptions,
}

impl BufferbloatBuilder {
    /// Set port to use
    pub fn port(mut self, port: u16) -> Self {
        self.options.port = port;
        self
    }

    /// Set number of baseline samples
    pub fn baseline_samples(mut self, count: usize) -> Self {
        self.options.baseline_samples = count;
        self
    }

    /// Set number of loaded samples
    pub fn loaded_samples(mut self, count: usize) -> Self {
        self.options.loaded_samples = count;
        self
    }

    /// Execute bufferbloat detection
    pub async fn send(self) -> crate::Result<BufferbloatResult> {
        analytics::detect_bufferbloat(&self.target, &self.options).await
    }
}

/// ICMP probe builder
pub struct IcmpProbe {
    target: String,
    options: ProbeOptions,
}

impl IcmpProbe {
    /// Set timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.options.timeout = timeout;
        self
    }

    /// Set TTL
    pub fn ttl(mut self, ttl: u8) -> Self {
        self.options.ttl = Some(ttl);
        self
    }

    /// Execute the probe
    pub async fn send(self) -> crate::Result<ProbeResult> {
        icmp::probe(&self.target, &self.options).await
    }
}

/// TCP probe builder
pub struct TcpProbe {
    target: String,
    port: u16,
    options: ProbeOptions,
}

impl TcpProbe {
    /// Set timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.options.timeout = timeout;
        self
    }

    /// Execute the probe
    pub async fn send(self) -> crate::Result<ProbeResult> {
        tcp::probe(&self.target, self.port, &self.options).await
    }
}

/// UDP probe builder
pub struct UdpProbe {
    target: String,
    port: u16,
    options: ProbeOptions,
}

impl UdpProbe {
    /// Set timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.options.timeout = timeout;
        self
    }

    /// Execute the probe
    pub async fn send(self) -> crate::Result<ProbeResult> {
        udp::probe(&self.target, self.port, &self.options).await
    }
}

/// Multi-protocol probe builder
pub struct MultiProbe {
    target: String,
    protocols: Vec<Protocol>,
    options: ProbeOptions,
}

impl MultiProbe {
    /// Add ICMP probe
    pub fn icmp(mut self) -> Self {
        self.protocols.push(Protocol::Icmp);
        self
    }

    /// Add TCP probe for a port
    pub fn tcp(mut self, port: u16) -> Self {
        self.protocols.push(Protocol::Tcp(port));
        self
    }

    /// Add UDP probe for a port
    pub fn udp(mut self, port: u16) -> Self {
        self.protocols.push(Protocol::Udp(port));
        self
    }

    /// Set timeout for all probes
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.options.timeout = timeout;
        self
    }

    /// Execute all probes concurrently
    ///
    /// DNS resolution is performed once and shared across all probes
    /// to avoid redundant lookups and ensure consistent targeting.
    pub async fn send(self) -> crate::Result<MultiProbeResult> {
        use crate::dns;
        use std::time::Instant;

        if self.protocols.is_empty() {
            return Err(Error::InvalidTarget("No protocols specified".to_string()));
        }

        // Resolve DNS once upfront
        let dns_start = Instant::now();
        let dns_result = dns::resolve_ipv4(&self.target).await?;
        let dns_time = dns_start.elapsed();
        let resolved_ip = dns_result.ip;

        // Use the resolved IP for all probes (pass as IP string to skip DNS)
        let ip_string = resolved_ip.to_string();

        let futures: Vec<_> = self.protocols.iter().map(|proto| {
            let target = ip_string.clone();
            let original_target = self.target.clone();
            let options = self.options.clone();
            let dns_duration = dns_time;

            async move {
                let mut result = match proto {
                    Protocol::Icmp => icmp::probe(&target, &options).await,
                    Protocol::Tcp(port) => tcp::probe(&target, *port, &options).await,
                    Protocol::Udp(port) => udp::probe(&target, *port, &options).await,
                };

                // Update result with original target name and shared DNS time
                if let Ok(ref mut r) = result {
                    r.target = original_target;
                    if r.timing.dns_time.is_none() || r.timing.dns_time == Some(std::time::Duration::ZERO) {
                        r.timing.dns_time = Some(dns_duration);
                        r.timing.total_time = dns_duration + r.timing.connect_time + r.timing.response_time;
                    }
                }

                result
            }
        }).collect();

        let results: Vec<ProbeResult> = futures::future::join_all(futures)
            .await
            .into_iter()
            .filter_map(|r| r.ok())
            .collect();

        let classification = Some(Classifier::classify(&results));

        Ok(MultiProbeResult {
            target: self.target,
            results,
            classification,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tcp_probe_builder() {
        let result = Probe::tcp("google.com", 443)
            .timeout(Duration::from_secs(5))
            .send()
            .await;

        match result {
            Ok(r) => {
                println!("TCP probe result: success={}, timing={:?}", r.success, r.timing);
            }
            Err(e) => {
                println!("Probe failed (may be network): {e}");
            }
        }
    }

    #[tokio::test]
    async fn test_multi_probe_builder() {
        let result = Probe::multi("google.com")
            .tcp(80)
            .tcp(443)
            .timeout(Duration::from_secs(5))
            .send()
            .await;

        match result {
            Ok(r) => {
                println!("Multi-probe results:");
                for probe in &r.results {
                    println!("  {}: success={}", probe.protocol, probe.success);
                }
                println!("Classification: {}", r.classify());
            }
            Err(e) => {
                println!("Multi-probe failed: {e}");
            }
        }
    }
}
