# Contributing to multiprobe

Thank you for your interest in contributing to multiprobe! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please be respectful and constructive in all interactions. We welcome contributors of all experience levels.

## Ways to Contribute

- **Bug Reports**: Open an issue with a clear description and minimal reproduction steps
- **Feature Requests**: Open an issue describing the use case and proposed solution
- **Code Contributions**: Submit a pull request (see below)
- **Documentation**: Improve README, examples, or inline documentation
- **Testing**: Add test cases, especially edge cases

## Development Setup

```bash
# Clone the repository
git clone https://github.com/biplabku/multiprobe.git
cd multiprobe

# Build
cargo build

# Run tests
cargo test

# Run clippy
cargo clippy --all-targets

# Format code
cargo fmt
```

## Pull Request Process

1. **Fork** the repository
2. **Create a branch** for your changes: `git checkout -b feature/my-feature`
3. **Make your changes** following the code style guidelines below
4. **Add tests** for any new functionality
5. **Run the full test suite**: `cargo test`
6. **Run clippy**: `cargo clippy --all-targets`
7. **Format code**: `cargo fmt`
8. **Commit** with a clear message describing the change
9. **Push** to your fork and open a pull request

## Code Style Guidelines

- Follow standard Rust conventions (rustfmt)
- Keep functions small and focused
- Add documentation for public APIs
- Prefer explicit error handling over panics
- Minimize unsafe code; justify any unsafe blocks with comments

## Testing Requirements

- All new features must have tests
- All bug fixes should include a regression test
- Tests should be deterministic (avoid flaky tests)
- Use `#[tokio::test]` for async tests

### Test Organization

```
tests/
  edge_cases.rs    # Integration tests for edge cases
src/
  module/
    mod.rs         # Unit tests in #[cfg(test)] mod tests
```

## Feature Requests

Before implementing a major feature:

1. Open an issue to discuss the design
2. Wait for feedback from maintainers
3. Reference the issue in your PR

## Areas We'd Love Help With

- IPv6 support
- Additional protocol probes (QUIC, HTTP/3)
- Platform-specific optimizations
- Performance benchmarks
- Documentation improvements
- Example applications

## Questions?

Open an issue with the "question" label or reach out to the maintainers.

## License

By contributing, you agree that your contributions will be licensed under the MIT OR Apache-2.0 license.
