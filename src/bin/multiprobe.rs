//! multiprobe CLI - Network probing and path analysis tool
//!
//! Usage: multiprobe <COMMAND> [OPTIONS] <TARGET>

use std::time::Duration;

use clap::{Parser, Subcommand};
use multiprobe::{
    Probe, Classifier, BidirectionalServer,
    paris::ParisMode,
    divergence::{analyze_divergence, DivergenceOptions, DivergenceProtocol},
    bgp::{correlate_divergence, CorrelationOptions},
};

#[derive(Parser)]
#[command(name = "multiprobe")]
#[command(author = "Biplab Das")]
#[command(version)]
#[command(about = "Multi-protocol network probing and path analysis tool")]
#[command(long_about = "Enterprise-grade network probing with Paris Traceroute, \
    path analytics, MTU discovery, bufferbloat detection, and bidirectional path analysis.")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// TCP connect probe
    Tcp {
        /// Target hostname or IP
        target: String,
        /// Port to probe
        port: u16,
        /// Timeout in seconds
        #[arg(short, long, default_value = "5")]
        timeout: u64,
    },

    /// UDP probe
    Udp {
        /// Target hostname or IP
        target: String,
        /// Port to probe
        port: u16,
        /// Timeout in seconds
        #[arg(short, long, default_value = "5")]
        timeout: u64,
    },

    /// ICMP ping (requires elevated privileges)
    Icmp {
        /// Target hostname or IP
        target: String,
        /// Timeout in seconds
        #[arg(short, long, default_value = "5")]
        timeout: u64,
        /// TTL (time to live)
        #[arg(long)]
        ttl: Option<u8>,
    },

    /// TLS handshake analysis
    Tls {
        /// Target hostname or IP
        target: String,
        /// Port (default 443)
        #[arg(short, long, default_value = "443")]
        port: u16,
        /// Timeout in seconds
        #[arg(short, long, default_value = "10")]
        timeout: u64,
        /// Skip certificate verification
        #[arg(long)]
        skip_verify: bool,
    },

    /// Standard traceroute (requires elevated privileges)
    Traceroute {
        /// Target hostname or IP
        target: String,
        /// Maximum hops
        #[arg(short, long, default_value = "30")]
        max_hops: u8,
        /// Timeout per hop in seconds
        #[arg(short, long, default_value = "2")]
        timeout: u64,
    },

    /// Paris Traceroute - ECMP-aware path discovery (requires elevated privileges)
    Paris {
        /// Target hostname or IP
        target: String,
        /// Maximum hops
        #[arg(short, long, default_value = "30")]
        max_hops: u8,
        /// Timeout per hop in seconds
        #[arg(short, long, default_value = "2")]
        timeout: u64,
        /// Probe mode: udp, icmp, tcp
        #[arg(long, default_value = "udp")]
        mode: String,
        /// Detect load balancing
        #[arg(long)]
        detect_lb: bool,
    },

    /// Multi-protocol probe (TCP, UDP, ICMP together)
    Multi {
        /// Target hostname or IP
        target: String,
        /// TCP ports to probe
        #[arg(long, value_delimiter = ',')]
        tcp: Vec<u16>,
        /// UDP ports to probe
        #[arg(long, value_delimiter = ',')]
        udp: Vec<u16>,
        /// Include ICMP ping
        #[arg(long)]
        icmp: bool,
        /// Timeout in seconds
        #[arg(short, long, default_value = "5")]
        timeout: u64,
    },

    /// Latency statistics (multiple samples)
    Latency {
        /// Target hostname or IP
        target: String,
        /// Port to probe
        port: u16,
        /// Number of samples
        #[arg(short, long, default_value = "20")]
        samples: usize,
        /// Interval between samples in milliseconds
        #[arg(short, long, default_value = "100")]
        interval: u64,
    },

    /// Path MTU discovery (requires elevated privileges)
    Mtu {
        /// Target hostname or IP
        target: String,
        /// Minimum MTU to test
        #[arg(long, default_value = "68")]
        min: u16,
        /// Maximum MTU to test
        #[arg(long, default_value = "1500")]
        max: u16,
        /// Timeout per probe in seconds
        #[arg(short, long, default_value = "2")]
        timeout: u64,
    },

    /// Bufferbloat detection
    Bufferbloat {
        /// Target hostname or IP
        target: String,
        /// Port to probe
        #[arg(short, long, default_value = "443")]
        port: u16,
        /// Baseline samples
        #[arg(long, default_value = "10")]
        baseline: usize,
        /// Loaded samples
        #[arg(long, default_value = "10")]
        loaded: usize,
    },

    /// Bidirectional path probing (requires multiprobe server on target)
    Bidirectional {
        /// Target hostname or IP (must be running multiprobe server)
        target: String,
        /// Port (default 33435)
        #[arg(short, long, default_value = "33435")]
        port: u16,
        /// Number of probes
        #[arg(short = 'c', long, default_value = "20")]
        count: u32,
        /// Interval between probes in milliseconds
        #[arg(short, long, default_value = "100")]
        interval: u64,
    },

    /// Start bidirectional probe server
    Server {
        /// Address to bind (default 0.0.0.0:33435)
        #[arg(short, long, default_value = "0.0.0.0:33435")]
        bind: String,
    },

    /// Protocol Divergence Localization - find where protocols behave differently (requires elevated privileges)
    Divergence {
        /// Target hostname or IP
        target: String,
        /// Maximum hops
        #[arg(short, long, default_value = "30")]
        max_hops: u8,
        /// Timeout per hop in seconds
        #[arg(short, long, default_value = "2")]
        timeout: u64,
        /// TCP port to probe
        #[arg(long, default_value = "80")]
        tcp_port: u16,
        /// UDP port to probe
        #[arg(long, default_value = "33434")]
        udp_port: u16,
        /// Protocols to use (comma-separated: icmp,tcp,udp)
        #[arg(long, default_value = "icmp,tcp,udp")]
        protocols: String,
    },

    /// BGP-correlated Protocol Divergence - correlate divergence with AS boundaries (requires elevated privileges)
    BgpDiverge {
        /// Target hostname or IP
        target: String,
        /// Maximum hops
        #[arg(short, long, default_value = "30")]
        max_hops: u8,
        /// Timeout per hop in seconds
        #[arg(short, long, default_value = "2")]
        timeout: u64,
        /// TCP port to probe
        #[arg(long, default_value = "80")]
        tcp_port: u16,
        /// UDP port to probe
        #[arg(long, default_value = "33434")]
        udp_port: u16,
        /// Protocols to use (comma-separated: icmp,tcp,udp)
        #[arg(long, default_value = "icmp,tcp,udp")]
        protocols: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = run_command(&cli).await;

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn run_command(cli: &Cli) -> Result<(), multiprobe::Error> {
    match &cli.command {
        Commands::Tcp { target, port, timeout } => {
            let result = Probe::tcp(target, *port)
                .timeout(Duration::from_secs(*timeout))
                .send()
                .await?;

            println!("TCP Probe: {}:{}", target, port);
            println!("  Success:  {}", result.success);
            println!("  IP:       {}", result.resolved_ip);
            println!("  Latency:  {:.2}ms", result.timing.total_ms());
            if let Some(dns) = result.timing.dns_time {
                println!("  DNS:      {:.2}ms", dns.as_secs_f64() * 1000.0);
            }
            println!("  Connect:  {:.2}ms", result.timing.connect_time.as_secs_f64() * 1000.0);
        }

        Commands::Udp { target, port, timeout } => {
            let result = Probe::udp(target, *port)
                .timeout(Duration::from_secs(*timeout))
                .send()
                .await?;

            println!("UDP Probe: {}:{}", target, port);
            println!("  Success:  {}", result.success);
            println!("  IP:       {}", result.resolved_ip);
            println!("  Latency:  {:.2}ms", result.timing.total_ms());
        }

        Commands::Icmp { target, timeout, ttl } => {
            let mut probe = Probe::icmp(target)
                .timeout(Duration::from_secs(*timeout));

            if let Some(t) = ttl {
                probe = probe.ttl(*t);
            }

            let result = probe.send().await?;

            println!("ICMP Ping: {}", target);
            println!("  Success:  {}", result.success);
            println!("  IP:       {}", result.resolved_ip);
            println!("  Latency:  {:.2}ms", result.timing.total_ms());
        }

        Commands::Tls { target, port, timeout, skip_verify } => {
            let mut probe = Probe::tls(target)
                .port(*port)
                .timeout(Duration::from_secs(*timeout));

            if *skip_verify {
                probe = probe.skip_verify();
            }

            let result = probe.send().await?;

            println!("TLS Probe: {}:{}", target, port);
            println!("  Success:    {}", result.success);
            println!("  Version:    {}", result.tls_version);
            if let Some(cipher) = &result.cipher_suite {
                println!("  Cipher:     {}", cipher);
            }
            println!("  HTTP/2:     {}", result.supports_http2());
            println!("  Modern TLS: {}", result.is_modern_tls());
            println!("\nTiming:");
            println!("  DNS:   {:.2}ms", result.timing.dns_ms());
            println!("  TCP:   {:.2}ms", result.timing.tcp_ms());
            println!("  TLS:   {:.2}ms", result.timing.tls_ms());
            println!("  Total: {:.2}ms", result.timing.total_ms());
        }

        Commands::Traceroute { target, max_hops, timeout } => {
            let result = Probe::traceroute(target)
                .max_hops(*max_hops)
                .timeout_per_hop(Duration::from_secs(*timeout))
                .send()
                .await?;

            println!("Traceroute: {} ({})", target, result.target_ip);
            println!("Reached: {}\n", result.reached_destination);

            for hop in &result.hops {
                let addr = hop.addr.map(|a| a.to_string()).unwrap_or_else(|| "*".to_string());
                let rtt = hop.rtt.as_secs_f64() * 1000.0;
                println!("{:2}. {:15} {:.2}ms", hop.ttl, addr, rtt);
            }
        }

        Commands::Paris { target, max_hops, timeout, mode, detect_lb } => {
            let paris_mode = match mode.to_lowercase().as_str() {
                "udp" => ParisMode::Udp,
                "icmp" => ParisMode::Icmp,
                "tcp" => ParisMode::Tcp,
                _ => ParisMode::Udp,
            };

            let result = Probe::paris(target)
                .max_hops(*max_hops)
                .timeout_per_hop(Duration::from_secs(*timeout))
                .mode(paris_mode)
                .detect_load_balancing(*detect_lb)
                .send()
                .await?;

            println!("Paris Traceroute: {} ({})", target, result.target_ip);
            println!("Mode: {:?}", paris_mode);
            println!("Reached: {}", result.reached_destination);
            println!("Load Balancing: {}\n", result.load_balancing);

            for hop in &result.hops {
                let addr = hop.addr.map(|a| a.to_string()).unwrap_or_else(|| "*".to_string());
                let rtt = hop.rtt.as_secs_f64() * 1000.0;
                println!("{:2}. {:15} {:.2}ms", hop.ttl, addr, rtt);
            }
        }

        Commands::Multi { target, tcp, udp, icmp, timeout } => {
            let mut probe = Probe::multi(target)
                .timeout(Duration::from_secs(*timeout));

            for port in tcp {
                probe = probe.tcp(*port);
            }
            for port in udp {
                probe = probe.udp(*port);
            }
            if *icmp {
                probe = probe.icmp();
            }

            if tcp.is_empty() && udp.is_empty() && !*icmp {
                eprintln!("Error: Specify at least one protocol (--tcp, --udp, or --icmp)");
                std::process::exit(1);
            }

            let result = probe.send().await?;

            println!("Multi-Protocol Probe: {}", target);
            println!("Classification: {}\n", result.classify());

            for r in &result.results {
                let status = if r.success { "OK" } else { "FAIL" };
                println!("  {:8} {:6} {:.2}ms", r.protocol, status, r.timing.total_ms());
            }

            if result.results.len() >= 2 {
                let pds = Classifier::differential_score(&result.results);
                println!("\nProtocol Differential Score:");
                println!("  Consistency: {:.2}", pds.consistency);
                println!("  Behavior:    {}", pds.interpret());
            }
        }

        Commands::Latency { target, port, samples, interval } => {
            let result = Probe::latency(target, *port)
                .samples(*samples)
                .interval(Duration::from_millis(*interval))
                .send()
                .await?;

            println!("Latency Statistics: {}:{}", target, port);
            println!("  Samples:  {}/{}", result.success_count, result.sample_count);
            println!("  Loss:     {:.1}%", result.loss_rate * 100.0);
            println!();
            println!("  Min:      {:.2}ms", result.min_rtt.as_secs_f64() * 1000.0);
            println!("  Max:      {:.2}ms", result.max_rtt.as_secs_f64() * 1000.0);
            println!("  Mean:     {:.2}ms", result.mean_rtt.as_secs_f64() * 1000.0);
            println!("  Median:   {:.2}ms", result.median_rtt.as_secs_f64() * 1000.0);
            println!("  P95:      {:.2}ms", result.p95_rtt.as_secs_f64() * 1000.0);
            println!("  P99:      {:.2}ms", result.p99_rtt.as_secs_f64() * 1000.0);
            println!("  Jitter:   {:.2}ms", result.jitter.as_secs_f64() * 1000.0);
            println!("  StdDev:   {:.2}ms", result.std_dev.as_secs_f64() * 1000.0);

            if result.has_high_jitter() {
                println!("\n  WARNING: High jitter detected!");
            }
            if result.has_packet_loss() {
                println!("  WARNING: Packet loss detected!");
            }
        }

        Commands::Mtu { target, min, max, timeout } => {
            let result = Probe::mtu(target)
                .min_mtu(*min)
                .max_mtu(*max)
                .timeout(Duration::from_secs(*timeout))
                .send()
                .await?;

            println!("Path MTU Discovery: {}", target);
            println!("  Path MTU:       {} bytes", result.path_mtu);
            println!("  DF Honored:     {}", result.df_honored);
            println!("  Frag Needed:    {} messages", result.frag_needed_count);
        }

        Commands::Bufferbloat { target, port, baseline, loaded } => {
            let result = Probe::bufferbloat(target)
                .port(*port)
                .baseline_samples(*baseline)
                .loaded_samples(*loaded)
                .send()
                .await?;

            println!("Bufferbloat Detection: {}:{}", target, port);
            println!("  Baseline:     {:.2}ms", result.baseline_latency.as_secs_f64() * 1000.0);
            println!("  Under Load:   {:.2}ms", result.loaded_latency.as_secs_f64() * 1000.0);
            println!("  Bloat Factor: {:.2}x", result.bloat_factor);
            println!("  Grade:        {}", result.grade);
            println!("  Detected:     {}", result.detected);
        }

        Commands::Bidirectional { target, port, count, interval } => {
            let result = Probe::bidirectional(target)
                .port(*port)
                .probe_count(*count)
                .interval(Duration::from_millis(*interval))
                .send()
                .await?;

            println!("Bidirectional Path Analysis: {}:{}", target, port);
            println!();
            println!("Forward Path (client -> server):");
            println!("  Sent:     {}", result.forward.sent);
            println!("  Received: {}", result.forward.received);
            println!("  Loss:     {:.1}%", result.forward.loss_percent());
            let fwd_min = if result.forward.min_ms == f64::MAX { 0.0 } else { result.forward.min_ms };
            println!("  Min:      {:.2}ms", fwd_min);
            println!("  Max:      {:.2}ms", result.forward.max_ms);
            println!("  Mean:     {:.2}ms", result.forward.mean_ms);
            println!("  Jitter:   {:.2}ms", result.forward.jitter_ms);
            println!();
            println!("Reverse Path (server -> client):");
            println!("  Sent:     {}", result.reverse.sent);
            println!("  Received: {}", result.reverse.received);
            println!("  Loss:     {:.1}%", result.reverse.loss_percent());
            let rev_min = if result.reverse.min_ms == f64::MAX { 0.0 } else { result.reverse.min_ms };
            println!("  Min:      {:.2}ms", rev_min);
            println!("  Max:      {:.2}ms", result.reverse.max_ms);
            println!("  Mean:     {:.2}ms", result.reverse.mean_ms);
            println!("  Jitter:   {:.2}ms", result.reverse.jitter_ms);
            println!();
            println!("Round Trip:");
            println!("  Mean:     {:.2}ms", result.round_trip.mean_ms);
            println!();
            println!("Asymmetry:");
            println!("  Score:    {:.2}", result.asymmetry_score);
            println!("  Status:   {}", result.interpretation());

            if result.asymmetric {
                println!("\n  WARNING: Significant path asymmetry detected!");
            }
        }

        Commands::Server { bind } => {
            println!("Starting multiprobe bidirectional server on {}...", bind);
            println!("Press Ctrl+C to stop.\n");

            let server = BidirectionalServer::bind(bind).await?;
            let addr = server.local_addr()?;
            println!("Listening on {}", addr);

            tokio::select! {
                result = server.run() => {
                    result?;
                }
                _ = tokio::signal::ctrl_c() => {
                    println!("\nShutting down...");
                    server.stop();
                }
            }

            println!("Server stopped. Handled {} probes.", server.probes_handled());
        }

        Commands::Divergence { target, max_hops, timeout, tcp_port, udp_port, protocols } => {
            let mut protos = Vec::new();
            for p in protocols.to_lowercase().split(',') {
                match p.trim() {
                    "icmp" => protos.push(DivergenceProtocol::Icmp),
                    "tcp" => protos.push(DivergenceProtocol::Tcp),
                    "udp" => protos.push(DivergenceProtocol::Udp),
                    _ => eprintln!("Warning: Unknown protocol '{}', ignoring", p),
                }
            }

            if protos.is_empty() {
                eprintln!("Error: No valid protocols specified");
                std::process::exit(1);
            }

            let options = DivergenceOptions {
                max_hops: *max_hops,
                timeout_per_hop: Duration::from_secs(*timeout),
                protocols: protos,
                tcp_port: *tcp_port,
                udp_port: *udp_port,
            };

            let result = analyze_divergence(target, &options).await?;

            println!("Protocol Divergence Analysis: {} ({})", target, result.target_ip);
            println!("Protocols: {:?}", result.protocols_used.iter().map(|p| p.to_string()).collect::<Vec<_>>());
            println!();

            // Print header
            print!("{:>3} ", "Hop");
            for proto in &result.protocols_used {
                print!("{:^20} ", proto.to_string());
            }
            println!("{:>10}", "Status");
            println!("{}", "-".repeat(3 + 21 * result.protocols_used.len() + 10));

            // Print each hop
            for hop in &result.hops {
                print!("{:>3} ", hop.ttl);

                for proto in &result.protocols_used {
                    let status = hop.results.get(proto)
                        .map(|s| format!("{}", s))
                        .unwrap_or_else(|| "?".to_string());
                    print!("{:^20} ", status);
                }

                let status_sym = if hop.has_divergence {
                    format!("⚠ DIVERGE")
                } else if hop.results.values().all(|s| s.is_success()) {
                    "✓".to_string()
                } else if hop.results.values().all(|s| !s.is_success()) {
                    "*".to_string()
                } else {
                    "?".to_string()
                };
                println!("{:>10}", status_sym);
            }

            println!();
            println!("Summary:");
            println!("  {}", result.summary());

            if let Some(hop_num) = result.first_divergence_hop {
                println!();
                println!("  First divergence at hop {}", hop_num);
                if let Some(hop) = result.divergence_point() {
                    if let Some(desc) = &hop.divergence_description {
                        println!("  Reason: {}", desc);
                    }
                }
            }

            println!();
            println!("  Path divergence score: {:.2}", result.path_divergence_score);
            println!("  Protocols reached destination: {:?}",
                result.protocols_reached.iter().map(|p| p.to_string()).collect::<Vec<_>>());
            println!("  Total time: {:.2}s", result.total_time.as_secs_f64());
        }

        Commands::BgpDiverge { target, max_hops, timeout, tcp_port, udp_port, protocols } => {
            let mut protos = Vec::new();
            for p in protocols.to_lowercase().split(',') {
                match p.trim() {
                    "icmp" => protos.push(DivergenceProtocol::Icmp),
                    "tcp" => protos.push(DivergenceProtocol::Tcp),
                    "udp" => protos.push(DivergenceProtocol::Udp),
                    _ => eprintln!("Warning: Unknown protocol '{}', ignoring", p),
                }
            }

            if protos.is_empty() {
                eprintln!("Error: No valid protocols specified");
                std::process::exit(1);
            }

            let options = CorrelationOptions {
                divergence: DivergenceOptions {
                    max_hops: *max_hops,
                    timeout_per_hop: Duration::from_secs(*timeout),
                    protocols: protos,
                    tcp_port: *tcp_port,
                    udp_port: *udp_port,
                },
                lookup_as_names: true,
                cache_asn: true,
            };

            let result = correlate_divergence(target, &options).await?;

            println!("BGP-Correlated Protocol Divergence: {} ({})", target, result.target_ip);
            println!();

            // Print AS path
            println!("AS Path: {}", result.as_path_str());
            println!("AS Transitions: {}", result.as_transitions);
            println!();

            // Print header
            println!("{:>3} {:^15} {:^8} {:^25} {:>10}", "Hop", "IP", "ASN", "AS Name", "Status");
            println!("{}", "-".repeat(70));

            // Print each hop
            for hop in &result.hops {
                let ip = hop.addr.map(|a| a.to_string()).unwrap_or_else(|| "*".to_string());
                let asn = hop.asn().map(|a| format!("AS{}", a)).unwrap_or_else(|| "-".to_string());
                let as_name = hop.asn_info.as_ref()
                    .and_then(|i| i.as_name.as_ref())
                    .map(|s| if s.len() > 22 { format!("{}...", &s[..22]) } else { s.clone() })
                    .unwrap_or_else(|| "-".to_string());

                let status = if hop.has_divergence {
                    if hop.is_as_boundary {
                        "⚠ AS-BOUND"
                    } else {
                        "⚠ INTRA-AS"
                    }
                } else if hop.is_as_boundary {
                    "→ boundary"
                } else {
                    "✓"
                };

                println!("{:>3} {:^15} {:^8} {:^25} {:>10}", hop.ttl, ip, asn, as_name, status);
            }

            println!();
            println!("AS-Boundary Divergence Score (ABDS):");
            println!("  Total divergent hops: {}", result.abds.total_divergent);
            println!("  At AS boundary:       {}", result.abds.at_boundary);
            println!("  Within AS (intra-AS): {}", result.abds.intra_as);
            println!("  Unknown location:     {}", result.abds.unknown);
            println!("  ABDS Score:           {:.2}", result.abds.score);
            println!("  Interpretation:       {}", result.abds.interpretation);

            println!();
            println!("Primary Cause: {}", result.primary_cause);
            println!();
            println!("Summary: {}", result.summary());
            println!("Total time: {:.2}s", result.total_time.as_secs_f64());
        }
    }

    Ok(())
}
