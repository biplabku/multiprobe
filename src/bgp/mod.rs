//! BGP-Correlated Protocol Divergence Analysis
//!
//! Combines active multi-protocol probing with BGP routing state to determine
//! whether protocol divergence is caused by policy (firewall/ACL) or routing.
//!
//! # Novel Contributions
//!
//! 1. **AS-Boundary Divergence Score (ABDS)**: Quantifies correlation between
//!    protocol divergence and AS boundaries
//! 2. **Control-Plane/Data-Plane Correlation**: Maps active path measurements
//!    to BGP routing state
//! 3. **Policy vs Routing Classification**: Determines root cause of divergence

mod asn_lookup;
mod correlation;

pub use asn_lookup::{AsnLookup, AsnInfo, AsnLookupError};
pub use correlation::{
    BgpCorrelatedResult, BgpCorrelatedHop, CorrelationOptions,
    DivergenceCause, AsBoundaryDivergenceScore,
    correlate_divergence,
};
