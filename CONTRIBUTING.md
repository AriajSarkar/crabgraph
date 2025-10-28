# Contributing to CrabGraph

Thank you for your interest in contributing to CrabGraph! This document provides guidelines and instructions for contributing.

## Table of Contents
- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Security Considerations](#security-considerations)

## Code of Conduct

This project adheres to a Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to ariajsarkar@gmail.com.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/AriajSarkar/crabgraph.git
   cd crabgraph
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/AriajSarkar/crabgraph.git
   ```

## Development Setup

### Prerequisites
- Rust 1.70+ (use `rustup` to install)
- Cargo and cargo tools:
  ```bash
  cargo install cargo-audit
  cargo install cargo-fuzz
  cargo install cargo-criterion
  ```

### Building
```bash
# Build with all features
cargo build --all-features

# Run tests
cargo test --all-features

# Run clippy
cargo clippy --all-features -- -D warnings

# Format code
cargo fmt --all
```

## How to Contribute

### Reporting Bugs
- Use the GitHub issue tracker
- Check if the issue already exists
- Include:
  - Rust version (`rustc --version`)
  - OS and version
  - Minimal reproducible example
  - Expected vs actual behavior

### Suggesting Enhancements
- Open a GitHub issue with the `enhancement` label
- Clearly describe the feature and its use case
- Explain why it would be useful to most users
- Consider backward compatibility

### Code Contributions
1. **Pick an issue** or propose a new feature
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/my-feature
   ```
3. **Make your changes** following our coding standards
4. **Write tests** for new functionality
5. **Update documentation** as needed
6. **Commit** with clear messages:
   ```bash
   git commit -m "feat: add X25519 key serialization"
   ```
7. **Push** to your fork:
   ```bash
   git push origin feature/my-feature
   ```
8. **Open a Pull Request** on GitHub

## Coding Standards

### Rust Style
- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `cargo fmt` (enforced in CI)
- Fix all `cargo clippy` warnings
- Write idiomatic Rust 2021 edition code

### Naming Conventions
- Types: `PascalCase` (e.g., `AesGcm256`, `Ed25519KeyPair`)
- Functions: `snake_case` (e.g., `derive_key`, `hmac_sha256`)
- Constants: `SCREAMING_SNAKE_CASE` (e.g., `DEFAULT_ITERATIONS`)
- Modules: `snake_case` (e.g., `kdf`, `aead`)

### Documentation
- All public items must have doc comments (`///`)
- Include examples in doc comments where possible
- Document panics, errors, and safety considerations
- Keep examples compilable (tested by `cargo test --doc`)

Example:
```rust
/// Derives a key from a password using Argon2id.
///
/// # Arguments
/// * `password` - The password to derive from
/// * `salt` - A unique salt (≥16 bytes recommended)
/// * `key_len` - Desired output key length in bytes
///
/// # Returns
/// A `SecretVec` containing the derived key material
///
/// # Errors
/// Returns `CrabError::InvalidInput` if salt is too short
///
/// # Example
/// ```
/// use crabgraph::kdf::argon2_derive;
///
/// let key = argon2_derive(b"password", b"saltsaltsaltsalt", 32)?;
/// assert_eq!(key.len(), 32);
/// # Ok::<(), crabgraph::CrabError>(())
/// ```
pub fn argon2_derive(password: &[u8], salt: &[u8], key_len: usize) -> CrabResult<SecretVec> {
    // implementation
}
```

### Error Handling
- Use `Result<T, CrabError>` (aliased as `CrabResult<T>`)
- Never panic in library code (except for `unreachable!()` or `unimplemented!()` during development)
- Provide context in error messages
- Never leak sensitive data in error messages

## Testing Requirements

### Unit Tests
- Required for all new functionality
- Use `#[cfg(test)]` module at the end of each file
- Test edge cases and error conditions
- Use test vectors from RFCs/NIST where available

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_aes_gcm_rfc_vector() {
        // Test with known vectors
    }

    #[test]
    fn test_invalid_key_size() {
        let result = AesGcm256::new(&[0u8; 16]);
        assert!(result.is_err());
    }
}
```

### Integration Tests
- Place in `tests/` directory
- Test real-world scenarios
- Verify interoperability (e.g., with JavaScript libraries)

### Property-Based Tests
- Use `proptest` or `quickcheck` for invariants
- Example: verify encrypt/decrypt round-trips

### Benchmarks
- Add benchmarks for performance-critical code
- Place in `benches/` directory
- Use Criterion.rs

### Test Coverage
- Aim for >80% code coverage
- Critical paths (crypto operations) should have >95% coverage

## Pull Request Process

1. **Ensure all tests pass**:
   ```bash
   cargo test --all-features
   cargo clippy --all-features -- -D warnings
   cargo fmt --all -- --check
   ```

2. **Update documentation**:
   - Update README if adding features
   - Add/update doc comments
   - Update CHANGELOG.md

3. **Write a clear PR description**:
   - What does this PR do?
   - Why is this change needed?
   - How was it tested?
   - Any breaking changes?

4. **Request review** from maintainers

5. **Address feedback** promptly

6. **Squash commits** if requested before merge

### PR Title Format
Use conventional commit format:
- `feat: add Argon2 support`
- `fix: correct nonce generation in ChaCha20`
- `docs: update AEAD examples`
- `test: add RFC test vectors for HMAC`
- `refactor: simplify error handling`
- `perf: optimize key derivation`

## Security Considerations

### Cryptographic Code
- **Never implement crypto primitives from scratch**
- Use audited libraries (RustCrypto, dalek, etc.)
- Verify test vectors from authoritative sources (RFCs, NIST)
- Consider timing attacks and side channels
- Use `zeroize` for sensitive data

### Code Review
- Cryptographic PRs require extra scrutiny
- Changes to core crypto modules need maintainer approval
- Security-sensitive changes may require external review

### Testing
- Test failure paths (invalid keys, wrong sizes, etc.)
- Verify constant-time properties where applicable
- Fuzz new parsing/deserialization code

## Questions?

- Open a GitHub discussion
- Email: ariajsarkar@gmail.com
- Check existing issues and documentation

## License

By contributing, you agree that your contributions will be licensed under the same MIT OR Apache-2.0 dual license as the project.
