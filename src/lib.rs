//! # multiprobe
//!
//! Enterprise-grade multi-protocol network probing library with advanced path analytics.
//!
//! ## Features
//!
//! ### Protocol Probes
//! - **ICMP ping** - Standard ICMP echo requests with timing
//! - **TCP probe** - TCP connect probes to any port
//! - **UDP probe** - UDP packet probes with response detection
//! - **TLS probe** - TLS handshake timing and cipher analysis
//!
//! ### Path Discovery
//! - **Traceroute** - Standard path discovery with hop-by-hop analysis
//! - **Paris Traceroute** - ECMP-aware traceroute that maintains flow consistency
//! - **Multi-path discovery** - Find all paths through load balancers
//!
//! ### Path Analytics
//! - **Jitter analysis** - Statistical latency metrics (min/max/mean/p95/p99)
//! - **MTU Discovery** - Path MTU detection with binary search
//! - **Bufferbloat detection** - Measure latency under load
//! - **Packet reordering** - Detect out-of-order delivery
//!
//! ### Classification
//! - **Path classification** - Fingerprint network paths
//! - **Protocol Differential Score** - Quantify cross-protocol behavior differences
//! - **Load balancing detection** - Identify ECMP routing
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use multiprobe::{Probe, Protocol};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), multiprobe::Error> {
//!     // TCP probe with timing
//!     let result = Probe::tcp("example.com", 443).send().await?;
//!     println!("Latency: {:.2}ms", result.timing.total_ms());
//!
//!     // Multi-protocol analysis
//!     let multi = Probe::multi("example.com")
//!         .tcp(80).tcp(443).udp(53)
//!         .send().await?;
//!     println!("Classification: {}", multi.classify());
//!
//!     // Paris Traceroute (ECMP-aware)
//!     let trace = Probe::paris("example.com")
//!         .max_hops(30)
//!         .send().await?;
//!     println!("Load balancing: {}", trace.load_balancing);
//!
//!     Ok(())
//! }
//! ```

mod dns;
mod error;
mod icmp;
mod tcp;
mod types;
mod udp;
mod probe;
mod classifier;
mod traceroute;
pub mod paris;
pub mod analytics;
pub mod tls;
pub mod bidirectional;

pub use error::Error;
pub use types::{
    ProbeResult, ProbeOptions, Protocol, TimingBreakdown,
    MultiProbeResult, PathClassification,
};
pub use probe::{Probe, TracerouteBuilder};
pub use classifier::{Classifier, NetworkBehavior, ProtocolDifferentialScore};
pub use traceroute::{TracerouteHop, TracerouteResult, TracerouteOptions, traceroute};

// Paris Traceroute exports
pub use paris::{
    ParisTraceResult, ParisHop, ParisOptions, ParisMode, FlowId,
    LoadBalancingType, paris_traceroute, discover_paths,
};

// Analytics exports
pub use analytics::{
    LatencyStats, PmtudResult, PmtudOptions, BufferbloatResult,
    BufferbloatGrade, BufferbloatOptions, ReorderingResult,
    measure_latency, discover_path_mtu, detect_bufferbloat, analyze_reordering,
};

// TLS exports
pub use tls::{
    TlsProbeResult, TlsProbeOptions, TlsTimingBreakdown, TlsVersion,
    probe_tls, compare_tls,
};

// Bidirectional exports
pub use bidirectional::{
    BidirectionalResult, BidirectionalOptions, BidirectionalServer,
    DirectionStats, probe_bidirectional, DEFAULT_PORT as BIDIRECTIONAL_PORT,
};

/// Result type alias for multiprobe operations
pub type Result<T> = std::result::Result<T, Error>;
