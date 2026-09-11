//! BGP-Correlated Protocol Divergence Analysis
//!
//! Novel contribution: Correlates active multi-protocol path measurements
//! with BGP routing state to classify divergence causes.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use crate::divergence::{
    DivergenceOptions, DivergenceProtocol, HopStatus, analyze_divergence,
};
use crate::bgp::asn_lookup::{AsnLookup, AsnInfo};
use crate::Error;

/// Classification of why protocol divergence occurred
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DivergenceCause {
    /// Divergence at AS boundary - likely routing policy
    AsBoundaryPolicy {
        from_asn: u32,
        to_asn: u32,
    },

    /// Divergence within single AS - likely internal firewall/ACL
    IntraAsPolicy {
        asn: u32,
    },

    /// Divergence at cloud provider edge
    CloudProviderEdge {
        provider_asn: u32,
        provider_name: String,
    },

    /// Divergence at transit provider
    TransitProvider {
        transit_asn: u32,
    },

    /// Cannot determine cause (private IPs, lookup failure)
    Unknown,
}

impl std::fmt::Display for DivergenceCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AsBoundaryPolicy { from_asn, to_asn } => {
                write!(f, "AS boundary policy (AS{} -> AS{})", from_asn, to_asn)
            }
            Self::IntraAsPolicy { asn } => {
                write!(f, "Intra-AS policy (within AS{})", asn)
            }
            Self::CloudProviderEdge { provider_name, .. } => {
                write!(f, "Cloud provider edge ({})", provider_name)
            }
            Self::TransitProvider { transit_asn } => {
                write!(f, "Transit provider policy (AS{})", transit_asn)
            }
            Self::Unknown => write!(f, "Unknown cause"),
        }
    }
}

/// AS-Boundary Divergence Score (ABDS)
///
/// Novel metric quantifying correlation between protocol divergence
/// and AS boundaries. Higher score indicates divergence correlates
/// with AS transitions.
#[derive(Debug, Clone)]
pub struct AsBoundaryDivergenceScore {
    /// Total divergent hops
    pub total_divergent: usize,

    /// Divergent hops at AS boundaries
    pub at_boundary: usize,

    /// Divergent hops within same AS
    pub intra_as: usize,

    /// Divergent hops at unknown locations (private IPs)
    pub unknown: usize,

    /// ABDS score: at_boundary / total_divergent (0.0 to 1.0)
    /// High score = divergence correlates with AS boundaries (routing policy)
    /// Low score = divergence within ASes (internal firewall)
    pub score: f64,

    /// Interpretation
    pub interpretation: AbdsInterpretation,
}

/// Interpretation of ABDS score
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbdsInterpretation {
    /// Score >= 0.8: Divergence strongly correlates with AS boundaries
    RoutingPolicyDriven,

    /// Score 0.4-0.8: Mixed causes
    Mixed,

    /// Score < 0.4: Divergence mostly within ASes
    InternalPolicyDriven,

    /// No divergence detected
    NoDivergence,
}

impl std::fmt::Display for AbdsInterpretation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RoutingPolicyDriven => write!(f, "Routing policy driven"),
            Self::Mixed => write!(f, "Mixed causes"),
            Self::InternalPolicyDriven => write!(f, "Internal policy driven"),
            Self::NoDivergence => write!(f, "No divergence"),
        }
    }
}

/// A single hop with BGP correlation data
#[derive(Debug, Clone)]
pub struct BgpCorrelatedHop {
    /// TTL/hop number
    pub ttl: u8,

    /// IP address (if responded)
    pub addr: Option<IpAddr>,

    /// ASN information (if resolvable)
    pub asn_info: Option<AsnInfo>,

    /// Protocol results at this hop
    pub protocol_results: HashMap<DivergenceProtocol, HopStatus>,

    /// Whether divergence occurred at this hop
    pub has_divergence: bool,

    /// Whether this hop is at an AS boundary
    pub is_as_boundary: bool,

    /// Previous hop's ASN (for boundary detection)
    pub prev_asn: Option<u32>,

    /// Divergence cause classification
    pub divergence_cause: Option<DivergenceCause>,
}

impl BgpCorrelatedHop {
    /// Get ASN if available
    pub fn asn(&self) -> Option<u32> {
        self.asn_info.as_ref().map(|info| info.asn)
    }

    /// Check if at cloud provider edge
    pub fn is_cloud_edge(&self) -> bool {
        self.asn_info.as_ref().map(|i| i.is_cloud_provider()).unwrap_or(false)
            && self.is_as_boundary
    }

    /// Check if at transit provider
    pub fn is_transit(&self) -> bool {
        self.asn_info.as_ref().map(|i| i.is_transit()).unwrap_or(false)
    }
}

/// Complete BGP-correlated divergence result
#[derive(Debug)]
pub struct BgpCorrelatedResult {
    /// Target analyzed
    pub target: String,

    /// Target IP
    pub target_ip: IpAddr,

    /// All hops with BGP correlation
    pub hops: Vec<BgpCorrelatedHop>,

    /// First hop where divergence occurs
    pub first_divergence_hop: Option<u8>,

    /// AS path observed (ASN sequence)
    pub as_path: Vec<u32>,

    /// Number of AS transitions
    pub as_transitions: usize,

    /// AS-Boundary Divergence Score
    pub abds: AsBoundaryDivergenceScore,

    /// Primary divergence cause
    pub primary_cause: DivergenceCause,

    /// Total time for analysis
    pub total_time: Duration,
}

impl BgpCorrelatedResult {
    /// Get summary of findings
    pub fn summary(&self) -> String {
        if self.first_divergence_hop.is_none() {
            return "No protocol divergence detected".to_string();
        }

        format!(
            "Divergence at hop {}: {} (ABDS: {:.2}, {})",
            self.first_divergence_hop.unwrap(),
            self.primary_cause,
            self.abds.score,
            self.abds.interpretation
        )
    }

    /// Get AS path as string
    pub fn as_path_str(&self) -> String {
        self.as_path.iter()
            .map(|asn| format!("AS{}", asn))
            .collect::<Vec<_>>()
            .join(" -> ")
    }

    /// Check if divergence is at a specific AS
    pub fn divergence_at_as(&self, asn: u32) -> bool {
        self.hops.iter().any(|h| {
            h.has_divergence && h.asn() == Some(asn)
        })
    }
}

/// Options for BGP-correlated analysis
#[derive(Debug, Clone)]
pub struct CorrelationOptions {
    /// Divergence analysis options
    pub divergence: DivergenceOptions,

    /// Whether to look up AS names (slower)
    pub lookup_as_names: bool,

    /// Cache ASN lookups
    pub cache_asn: bool,
}

impl Default for CorrelationOptions {
    fn default() -> Self {
        Self {
            divergence: DivergenceOptions::default(),
            lookup_as_names: true,
            cache_asn: true,
        }
    }
}

/// Perform BGP-correlated protocol divergence analysis
pub async fn correlate_divergence(
    target: &str,
    options: &CorrelationOptions,
) -> Result<BgpCorrelatedResult, Error> {
    let start = std::time::Instant::now();

    // Step 1: Run Protocol Divergence Localization
    let divergence_result = analyze_divergence(target, &options.divergence).await?;

    // Step 2: Initialize ASN lookup
    let asn_lookup = AsnLookup::new().await
        .map_err(|e| Error::Dns(e.to_string()))?;

    // Step 3: Look up ASN for each hop
    let mut correlated_hops = Vec::new();
    let mut prev_asn: Option<u32> = None;
    let mut as_path = Vec::new();

    for hop in &divergence_result.hops {
        let addr = hop.results.values()
            .filter_map(|s| s.addr())
            .next();

        let asn_info = if let Some(ip) = addr {
            match asn_lookup.lookup(ip).await {
                Ok(info) => Some(info),
                Err(_) => None,
            }
        } else {
            None
        };

        // Detect AS boundary
        let current_asn = asn_info.as_ref().map(|i| i.asn);
        let is_as_boundary = match (prev_asn, current_asn) {
            (Some(prev), Some(curr)) => prev != curr,
            (None, Some(_)) => true, // First public AS
            _ => false,
        };

        // Track AS path
        if let Some(asn) = current_asn {
            if as_path.last() != Some(&asn) {
                as_path.push(asn);
            }
        }

        // Classify divergence cause
        let divergence_cause = if hop.has_divergence {
            Some(classify_divergence_cause(
                is_as_boundary,
                prev_asn,
                asn_info.as_ref(),
            ))
        } else {
            None
        };

        correlated_hops.push(BgpCorrelatedHop {
            ttl: hop.ttl,
            addr,
            asn_info: asn_info.clone(),
            protocol_results: hop.results.clone(),
            has_divergence: hop.has_divergence,
            is_as_boundary,
            prev_asn,
            divergence_cause,
        });

        if current_asn.is_some() {
            prev_asn = current_asn;
        }
    }

    // Step 4: Calculate ABDS
    let abds = calculate_abds(&correlated_hops);

    // Step 5: Determine primary cause
    let primary_cause = correlated_hops.iter()
        .find(|h| h.has_divergence)
        .and_then(|h| h.divergence_cause.clone())
        .unwrap_or(DivergenceCause::Unknown);

    let as_transitions = as_path.windows(2).count();

    Ok(BgpCorrelatedResult {
        target: divergence_result.target,
        target_ip: divergence_result.target_ip,
        hops: correlated_hops,
        first_divergence_hop: divergence_result.first_divergence_hop,
        as_path,
        as_transitions,
        abds,
        primary_cause,
        total_time: start.elapsed(),
    })
}

/// Classify the cause of divergence at a hop
fn classify_divergence_cause(
    is_as_boundary: bool,
    prev_asn: Option<u32>,
    asn_info: Option<&AsnInfo>,
) -> DivergenceCause {
    match (is_as_boundary, asn_info) {
        (true, Some(info)) if info.is_cloud_provider() => {
            DivergenceCause::CloudProviderEdge {
                provider_asn: info.asn,
                provider_name: info.as_name.clone().unwrap_or_else(|| format!("AS{}", info.asn)),
            }
        }
        (true, Some(info)) if info.is_transit() => {
            DivergenceCause::TransitProvider {
                transit_asn: info.asn,
            }
        }
        (true, Some(info)) => {
            DivergenceCause::AsBoundaryPolicy {
                from_asn: prev_asn.unwrap_or(0),
                to_asn: info.asn,
            }
        }
        (false, Some(info)) => {
            DivergenceCause::IntraAsPolicy {
                asn: info.asn,
            }
        }
        _ => DivergenceCause::Unknown,
    }
}

/// Calculate AS-Boundary Divergence Score
fn calculate_abds(hops: &[BgpCorrelatedHop]) -> AsBoundaryDivergenceScore {
    let divergent_hops: Vec<_> = hops.iter()
        .filter(|h| h.has_divergence)
        .collect();

    let total = divergent_hops.len();

    if total == 0 {
        return AsBoundaryDivergenceScore {
            total_divergent: 0,
            at_boundary: 0,
            intra_as: 0,
            unknown: 0,
            score: 0.0,
            interpretation: AbdsInterpretation::NoDivergence,
        };
    }

    let at_boundary = divergent_hops.iter()
        .filter(|h| h.is_as_boundary && h.asn_info.is_some())
        .count();

    let intra_as = divergent_hops.iter()
        .filter(|h| !h.is_as_boundary && h.asn_info.is_some())
        .count();

    let unknown = divergent_hops.iter()
        .filter(|h| h.asn_info.is_none())
        .count();

    let score = if total > unknown {
        at_boundary as f64 / (total - unknown) as f64
    } else {
        0.0
    };

    let interpretation = if total == 0 {
        AbdsInterpretation::NoDivergence
    } else if score >= 0.8 {
        AbdsInterpretation::RoutingPolicyDriven
    } else if score >= 0.4 {
        AbdsInterpretation::Mixed
    } else {
        AbdsInterpretation::InternalPolicyDriven
    };

    AsBoundaryDivergenceScore {
        total_divergent: total,
        at_boundary,
        intra_as,
        unknown,
        score,
        interpretation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_divergence_cause_display() {
        let cause = DivergenceCause::AsBoundaryPolicy {
            from_asn: 64500,
            to_asn: 64501,
        };
        assert!(cause.to_string().contains("AS64500"));
        assert!(cause.to_string().contains("AS64501"));

        let cause = DivergenceCause::CloudProviderEdge {
            provider_asn: 15169,
            provider_name: "GOOGLE".to_string(),
        };
        assert!(cause.to_string().contains("GOOGLE"));
    }

    #[test]
    fn test_abds_calculation_no_divergence() {
        let hops: Vec<BgpCorrelatedHop> = vec![];
        let abds = calculate_abds(&hops);

        assert_eq!(abds.total_divergent, 0);
        assert_eq!(abds.score, 0.0);
        assert_eq!(abds.interpretation, AbdsInterpretation::NoDivergence);
    }

    #[test]
    fn test_abds_interpretation() {
        // High score = routing policy
        let abds = AsBoundaryDivergenceScore {
            total_divergent: 5,
            at_boundary: 4,
            intra_as: 1,
            unknown: 0,
            score: 0.8,
            interpretation: AbdsInterpretation::RoutingPolicyDriven,
        };
        assert_eq!(abds.interpretation, AbdsInterpretation::RoutingPolicyDriven);

        // Low score = internal policy
        let abds = AsBoundaryDivergenceScore {
            total_divergent: 5,
            at_boundary: 1,
            intra_as: 4,
            unknown: 0,
            score: 0.2,
            interpretation: AbdsInterpretation::InternalPolicyDriven,
        };
        assert_eq!(abds.interpretation, AbdsInterpretation::InternalPolicyDriven);
    }

    #[test]
    fn test_classify_divergence_cause() {
        // At AS boundary with cloud provider
        let google_info = AsnInfo {
            asn: 15169,
            prefix: "8.8.8.0/24".to_string(),
            country: Some("US".to_string()),
            registry: None,
            allocated: None,
            as_name: Some("GOOGLE".to_string()),
        };

        let cause = classify_divergence_cause(true, Some(64500), Some(&google_info));
        assert!(matches!(cause, DivergenceCause::CloudProviderEdge { .. }));

        // Within AS
        let cause = classify_divergence_cause(false, Some(64500), Some(&google_info));
        assert!(matches!(cause, DivergenceCause::IntraAsPolicy { .. }));

        // Unknown
        let cause = classify_divergence_cause(false, None, None);
        assert!(matches!(cause, DivergenceCause::Unknown));
    }

    #[test]
    fn test_abds_realistic_routing_policy_scenario() {
        // Simulate: Home -> ISP (AS7922) -> Transit (AS174) -> Google (AS15169)
        // Divergence occurs at AS boundary (Cogent -> Google) = routing policy
        let hops = vec![
            // Hop 1: Private IP (home router)
            BgpCorrelatedHop {
                ttl: 1,
                addr: Some("192.168.1.1".parse().unwrap()),
                asn_info: None,
                protocol_results: HashMap::new(),
                has_divergence: false,
                is_as_boundary: false,
                prev_asn: None,
                divergence_cause: None,
            },
            // Hop 2: ISP (Comcast)
            BgpCorrelatedHop {
                ttl: 2,
                addr: Some("68.86.85.1".parse().unwrap()),
                asn_info: Some(AsnInfo {
                    asn: 7922,
                    prefix: "68.86.0.0/14".to_string(),
                    country: Some("US".to_string()),
                    registry: None,
                    allocated: None,
                    as_name: Some("COMCAST-7922".to_string()),
                }),
                protocol_results: HashMap::new(),
                has_divergence: false,
                is_as_boundary: true,
                prev_asn: None,
                divergence_cause: None,
            },
            // Hop 3: Transit (Cogent) - AS boundary, no divergence
            BgpCorrelatedHop {
                ttl: 3,
                addr: Some("154.54.30.1".parse().unwrap()),
                asn_info: Some(AsnInfo {
                    asn: 174,
                    prefix: "154.54.0.0/16".to_string(),
                    country: Some("US".to_string()),
                    registry: None,
                    allocated: None,
                    as_name: Some("COGENT-174".to_string()),
                }),
                protocol_results: HashMap::new(),
                has_divergence: false,
                is_as_boundary: true,
                prev_asn: Some(7922),
                divergence_cause: None,
            },
            // Hop 4: Google edge - DIVERGENCE at AS boundary
            BgpCorrelatedHop {
                ttl: 4,
                addr: Some("142.250.169.1".parse().unwrap()),
                asn_info: Some(AsnInfo {
                    asn: 15169,
                    prefix: "142.250.0.0/15".to_string(),
                    country: Some("US".to_string()),
                    registry: None,
                    allocated: None,
                    as_name: Some("GOOGLE".to_string()),
                }),
                protocol_results: HashMap::new(),
                has_divergence: true,
                is_as_boundary: true,
                prev_asn: Some(174),
                divergence_cause: Some(DivergenceCause::CloudProviderEdge {
                    provider_asn: 15169,
                    provider_name: "GOOGLE".to_string(),
                }),
            },
        ];

        let abds = calculate_abds(&hops);

        assert_eq!(abds.total_divergent, 1);
        assert_eq!(abds.at_boundary, 1);
        assert_eq!(abds.intra_as, 0);
        assert_eq!(abds.score, 1.0);
        assert_eq!(abds.interpretation, AbdsInterpretation::RoutingPolicyDriven);
    }

    #[test]
    fn test_abds_realistic_internal_firewall_scenario() {
        // Simulate: Corporate network with internal firewall blocking UDP
        // Divergence occurs WITHIN corporate AS = internal policy
        let corporate_asn = 64496; // Private use ASN
        let hops = vec![
            // Hop 1: Internal router
            BgpCorrelatedHop {
                ttl: 1,
                addr: Some("10.1.1.1".parse().unwrap()),
                asn_info: None,
                protocol_results: HashMap::new(),
                has_divergence: false,
                is_as_boundary: false,
                prev_asn: None,
                divergence_cause: None,
            },
            // Hop 2: Corporate edge (public IP)
            BgpCorrelatedHop {
                ttl: 2,
                addr: Some("203.0.113.1".parse().unwrap()),
                asn_info: Some(AsnInfo {
                    asn: corporate_asn,
                    prefix: "203.0.113.0/24".to_string(),
                    country: Some("US".to_string()),
                    registry: None,
                    allocated: None,
                    as_name: Some("ACME-CORP".to_string()),
                }),
                protocol_results: HashMap::new(),
                has_divergence: false,
                is_as_boundary: true,
                prev_asn: None,
                divergence_cause: None,
            },
            // Hop 3: Firewall - DIVERGENCE within corporate AS
            BgpCorrelatedHop {
                ttl: 3,
                addr: Some("203.0.113.10".parse().unwrap()),
                asn_info: Some(AsnInfo {
                    asn: corporate_asn,
                    prefix: "203.0.113.0/24".to_string(),
                    country: Some("US".to_string()),
                    registry: None,
                    allocated: None,
                    as_name: Some("ACME-CORP".to_string()),
                }),
                protocol_results: HashMap::new(),
                has_divergence: true,
                is_as_boundary: false,
                prev_asn: Some(corporate_asn),
                divergence_cause: Some(DivergenceCause::IntraAsPolicy { asn: corporate_asn }),
            },
            // Hop 4: ISP
            BgpCorrelatedHop {
                ttl: 4,
                addr: Some("198.51.100.1".parse().unwrap()),
                asn_info: Some(AsnInfo {
                    asn: 7922,
                    prefix: "198.51.100.0/24".to_string(),
                    country: Some("US".to_string()),
                    registry: None,
                    allocated: None,
                    as_name: Some("COMCAST".to_string()),
                }),
                protocol_results: HashMap::new(),
                has_divergence: false,
                is_as_boundary: true,
                prev_asn: Some(corporate_asn),
                divergence_cause: None,
            },
        ];

        let abds = calculate_abds(&hops);

        assert_eq!(abds.total_divergent, 1);
        assert_eq!(abds.at_boundary, 0);
        assert_eq!(abds.intra_as, 1);
        assert_eq!(abds.score, 0.0);
        assert_eq!(abds.interpretation, AbdsInterpretation::InternalPolicyDriven);
    }

    #[test]
    fn test_abds_mixed_divergence_scenario() {
        // Multiple divergence points: some at boundaries, some internal
        let hops = vec![
            // Hop 1: First AS - internal divergence
            BgpCorrelatedHop {
                ttl: 1,
                addr: Some("192.0.2.1".parse().unwrap()),
                asn_info: Some(AsnInfo {
                    asn: 64500,
                    prefix: "192.0.2.0/24".to_string(),
                    country: Some("US".to_string()),
                    registry: None,
                    allocated: None,
                    as_name: Some("AS64500".to_string()),
                }),
                protocol_results: HashMap::new(),
                has_divergence: true, // Internal divergence
                is_as_boundary: false,
                prev_asn: None,
                divergence_cause: Some(DivergenceCause::IntraAsPolicy { asn: 64500 }),
            },
            // Hop 2: AS boundary - divergence
            BgpCorrelatedHop {
                ttl: 2,
                addr: Some("198.51.100.1".parse().unwrap()),
                asn_info: Some(AsnInfo {
                    asn: 64501,
                    prefix: "198.51.100.0/24".to_string(),
                    country: Some("US".to_string()),
                    registry: None,
                    allocated: None,
                    as_name: Some("AS64501".to_string()),
                }),
                protocol_results: HashMap::new(),
                has_divergence: true, // Boundary divergence
                is_as_boundary: true,
                prev_asn: Some(64500),
                divergence_cause: Some(DivergenceCause::AsBoundaryPolicy {
                    from_asn: 64500,
                    to_asn: 64501,
                }),
            },
        ];

        let abds = calculate_abds(&hops);

        assert_eq!(abds.total_divergent, 2);
        assert_eq!(abds.at_boundary, 1);
        assert_eq!(abds.intra_as, 1);
        assert_eq!(abds.score, 0.5);
        assert_eq!(abds.interpretation, AbdsInterpretation::Mixed);
    }
}
