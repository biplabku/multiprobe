# GitHub Issues to Create

Go to: https://github.com/biplabku/multiprobe/issues/new

Create these issues and add labels: `good first issue`, `help wanted`, `enhancement`

---

## Issue 1: Add IPv6 Support

**Title:** `Add IPv6 support`

**Labels:** `enhancement`, `good first issue`, `help wanted`

**Body:**
```
## Description
Currently multiprobe only supports IPv4. Adding IPv6 support would make the library more versatile for modern networks.

## Tasks
- [ ] Update DNS resolution to handle AAAA records
- [ ] Add IPv6 socket handling in TCP/UDP probes  
- [ ] Update Paris Traceroute for IPv6
- [ ] Add IPv6 test cases

## Technical Notes
- `socket2` crate already supports IPv6
- May need to handle dual-stack scenarios
- ICMPv6 uses different type codes than ICMPv4

## References
- RFC 2460 (IPv6 Specification)
- RFC 4443 (ICMPv6)

This is a good first issue for someone familiar with IPv6 networking basics.
```

---

## Issue 2: Add QUIC/HTTP3 Probe Support

**Title:** `Add QUIC/HTTP3 probe support`

**Labels:** `enhancement`, `help wanted`

**Body:**
```
## Description
QUIC (HTTP/3) is increasingly common. Adding QUIC probing would allow measuring:
- QUIC handshake timing (vs TCP+TLS)
- 0-RTT connection resumption detection
- QUIC-specific path characteristics

## Proposed API
```rust
let quic = Probe::quic("example.com")
    .port(443)
    .send().await?;

println!("Handshake: {:.2}ms", quic.timing.handshake_ms());
println!("0-RTT: {}", quic.zero_rtt_supported);
```

## Technical Considerations
- Could use `quinn` crate for QUIC implementation
- Need to handle QUIC version negotiation
- Consider HTTP/3 ALPN detection

## References
- RFC 9000 (QUIC)
- RFC 9114 (HTTP/3)
```

---

## Issue 3: Add Benchmarks

**Title:** `Add performance benchmarks`

**Labels:** `enhancement`, `good first issue`, `documentation`

**Body:**
```
## Description
Add benchmarks to track performance and prevent regressions.

## Tasks
- [ ] Set up `criterion` for benchmarking
- [ ] Benchmark DNS resolution
- [ ] Benchmark TCP probe latency overhead
- [ ] Benchmark multi-protocol concurrent probes
- [ ] Add CI job for benchmark comparison

## Example Structure
```
benches/
  probes.rs      # Individual probe benchmarks
  concurrent.rs  # Concurrent probe benchmarks
```

Good first issue for learning Rust benchmarking with criterion.
```

---

## Issue 4: Add async-std Support

**Title:** `Add async-std runtime support`

**Labels:** `enhancement`, `help wanted`

**Body:**
```
## Description
Currently multiprobe requires tokio. Adding async-std support would help users who prefer that runtime.

## Approach Options
1. **Feature flags**: `tokio` (default) and `async-std` features
2. **Runtime-agnostic**: Use `async-io` or similar abstraction

## Tasks
- [ ] Research runtime abstraction options
- [ ] Implement feature-gated runtime support
- [ ] Update documentation
- [ ] Add CI testing for both runtimes

## Considerations
- `hickory-resolver` has runtime feature flags we can leverage
- Socket operations may need abstraction
```

---

## Issue 5: Improve Error Messages

**Title:** `Improve error messages with more context`

**Labels:** `enhancement`, `good first issue`

**Body:**
```
## Description
Some error messages could include more context to help users debug issues.

## Examples

Current:
```
Error: DNS resolution failed
```

Better:
```
Error: DNS resolution failed for 'example.com': NXDOMAIN (domain does not exist)
```

## Tasks
- [ ] Audit all error variants in `src/error.rs`
- [ ] Add context fields where helpful
- [ ] Update error Display implementations
- [ ] Add examples of common errors to docs

Good first issue for learning Rust error handling patterns.
```

---

## Issue 6: Add CI/CD with GitHub Actions

**Title:** `Set up GitHub Actions CI/CD`

**Labels:** `enhancement`, `good first issue`, `infrastructure`

**Body:**
```
## Description
Add automated testing and publishing via GitHub Actions.

## Proposed Workflows

### ci.yml
- Run on every PR and push to main
- Matrix: Ubuntu, macOS, Windows
- Steps: fmt check, clippy, test, doc build

### release.yml  
- Trigger on version tag (v*)
- Build and test
- Publish to crates.io
- Create GitHub release

## Tasks
- [ ] Create `.github/workflows/ci.yml`
- [ ] Create `.github/workflows/release.yml`
- [ ] Add status badges to README
- [ ] Document release process

## References
- [Rust GitHub Actions](https://github.com/actions-rs)
```

---

# After Creating Issues

1. **Screenshot the issues list** - shows community engagement setup
2. **Pin Issue #6 (CI/CD)** - shows professional project management
3. **Share issue links** in your Reddit/HN posts - invites contribution
