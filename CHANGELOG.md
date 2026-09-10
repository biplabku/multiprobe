# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-09-10

### Added

- **Protocol Divergence Localization** - New feature to find WHERE in a network path different protocols start behaving differently
  - Run ICMP, TCP, and UDP traceroutes in parallel
  - Compare results at each hop to detect divergence
  - Identify the first hop where protocols fail differently
  - Calculate per-hop agreement scores
  - New CLI command: `multiprobe divergence <target>`
  - Useful for diagnosing firewall rules, middlebox interference, or protocol-specific filtering

### Changed

- Updated crate description to highlight Protocol Divergence Localization

## [0.3.1] - 2026-09-10

### Fixed

- Removed non-essential files from crate package

## [0.3.0] - 2026-09-10

### Added

- **Bidirectional Path Probing** - Detect forward/reverse path asymmetry
  - Server mode: `multiprobe server`
  - Client mode: `multiprobe bidirectional <target>`
  - Measures latency, jitter, and loss in both directions
  - Calculates asymmetry score

- **CLI Binary** - Full-featured command-line tool
  - All features accessible via subcommands
  - Tab completion support

## [0.2.0] - 2026-09-09

### Added

- Paris Traceroute implementation
- TLS handshake analysis
- Latency statistics (min/max/mean/p95/p99)
- Path MTU discovery
- Bufferbloat detection
- Protocol Differential Score

## [0.1.0] - 2026-09-09

### Added

- Initial release
- TCP, UDP, ICMP probes
- Basic traceroute
- Multi-protocol probing
- Path classification
