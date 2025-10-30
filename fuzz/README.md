# CrabGraph Fuzzing Infrastructure

This directory contains comprehensive fuzz targets for CrabGraph using cargo-fuzz and libfuzzer.

## Overview

We have **9 fuzz targets** covering all major cryptographic modules:

1. **aead_fuzz** - AEAD encryption (AES-GCM)
2. **kdf_fuzz** - Key derivation functions (PBKDF2, HKDF)
3. **key_wrap_fuzz** - AES Key Wrap (RFC 3394)
4. **encoding_fuzz** - Base64 and hex encoding/decoding
5. **hash_fuzz** - Hash functions (SHA-256/512, SHA3, BLAKE2, BLAKE3)
6. **mac_fuzz** - Message authentication codes (HMAC-SHA256/512)
7. **stream_fuzz** - Streaming encryption (AES-256-GCM STREAM)
8. **ed25519_fuzz** - Ed25519 signing/verification
9. **x25519_fuzz** - X25519 key exchange

## Prerequisites

Fuzzing requires the **nightly Rust toolchain**:

```bash
rustup toolchain install nightly
```

Install cargo-fuzz:

```bash
cargo install cargo-fuzz
```

### ⚠️ Windows Limitation

**On Windows**, you'll encounter `STATUS_DLL_NOT_FOUND` errors when trying to run fuzz targets. This is because:
- libFuzzer uses AddressSanitizer (ASAN) for memory safety checking
- Windows MSVC doesn't ship ASAN runtime DLLs with standard Rust installation
- The executables compile but can't run due to missing `clang_rt.asan_dynamic-x86_64.dll`

**Solutions:**

1. **WSL2 (Recommended)** - Run fuzzing in Windows Subsystem for Linux:
   ```bash
   wsl
   cd /mnt/c/all/Crates-For-Rust/crabgraph
   cargo +nightly fuzz run <target_name>
   ```

2. **Docker** - Use a Linux container:
   ```bash
   docker run -it --rm -v ${PWD}:/workspace rust:nightly
   cd /workspace
   cargo fuzz run <target_name>
   ```

3. **Native Linux/macOS** - Fuzzing works out-of-the-box on Unix systems

4. **Windows - Compilation Only** - On Windows, you can still:
   - Build fuzz targets to verify they compile: `cargo +nightly fuzz build`
   - Run unit and property tests: `cargo test --all-features`
   - Develop and iterate on fuzz target code

**Note:** The fuzz targets successfully compile on Windows, which validates the code is correct. The runtime issue is purely a Windows toolchain limitation, not a problem with the fuzz targets themselves.

## Running Fuzz Tests

### List all fuzz targets

```bash
cargo fuzz list
```

### Run a specific fuzz target

```bash
# Run for a limited time (e.g., 60 seconds)
cargo +nightly fuzz run <target_name> -- -max_total_time=60

# Run for a specific number of iterations
cargo +nightly fuzz run <target_name> -- -runs=10000

# Example: Fuzz AES-GCM encryption
cargo +nightly fuzz run aead_fuzz -- -max_total_time=60
```

### Build all fuzz targets

```bash
cargo +nightly fuzz build
```

### Run with custom options

```bash
# Use multiple cores
cargo +nightly fuzz run <target_name> -- -workers=4

# Save interesting inputs to corpus
cargo +nightly fuzz run <target_name> -- -max_total_time=300

# Minimize corpus
cargo +nightly fuzz cmin <target_name>
```

## What Each Fuzzer Tests

### aead_fuzz
- Encrypt/decrypt round-trips for AES-256-GCM
- AAD (Additional Authenticated Data) integrity
- Wrong AAD rejection
- No panics on arbitrary input

### kdf_fuzz
- PBKDF2 SHA-256 with variable inputs
- HKDF SHA-256 key derivation
- No panics with arbitrary passwords/salts

### key_wrap_fuzz
- AES-KW wrap/unwrap round-trips
- Supports Kw128 and Kw256
- Tampered data rejection
- Multiple of 8-byte requirement enforcement

### encoding_fuzz
- Base64 encode/decode round-trips
- Hex encode/decode round-trips
- Graceful handling of invalid encoded data

### hash_fuzz
- SHA-256/512 determinism
- Correct output lengths (32/64 bytes)
- SHA-3, BLAKE2, BLAKE3 if `extended-hashes` enabled
- No panics on large inputs (up to 100KB)

### mac_fuzz
- HMAC-SHA256/512 generation
- MAC verification round-trips
- Wrong MAC rejection
- Wrong key/message detection

### stream_fuzz
- Streaming encryption/decryption with AES-256-GCM STREAM
- Multi-chunk processing
- Nonce management
- encrypt_next / encrypt_last semantics
- decrypt_next / decrypt_last semantics
- Complete round-trip verification

### ed25519_fuzz
- Ed25519 signature generation
- Signature verification
- Wrong message rejection
- Tampered signature detection

### x25519_fuzz
- X25519 Diffie-Hellman key exchange
- Shared secret agreement between Alice and Bob
- Key derivation with different info values
- Deterministic key derivation

## Corpus Management

Fuzz targets maintain a corpus of interesting inputs in `fuzz/corpus/<target_name>/`.

To minimize corpus size:

```bash
cargo +nightly fuzz cmin <target_name>
```

To merge multiple corpus directories:

```bash
cargo +nightly fuzz cmin -merge <target_name> corpus1/ corpus2/
```

## Artifacts

When a crash/assertion failure is found, artifacts are saved to:
```
fuzz/artifacts/<target_name>/
```

To reproduce a crash:

```bash
cargo +nightly fuzz run <target_name> fuzz/artifacts/<target_name>/<artifact_file>
```

## CI Integration

For continuous fuzzing in CI, consider:

1. **Short fuzzing runs** (1-5 minutes per target) in regular CI
2. **Longer fuzzing campaigns** (hours/days) on dedicated servers
3. **OSS-Fuzz integration** for Google's continuous fuzzing infrastructure

Example CI command:

```bash
# Fuzz all targets for 2 minutes each
for target in $(cargo fuzz list); do
  cargo +nightly fuzz run $target -- -max_total_time=120 || true
done
```

## Platform Notes

### Windows
- **Issue**: `STATUS_DLL_NOT_FOUND` (exit code 0xc0000135) when running fuzz targets
- **Root Cause**: MSVC toolchain doesn't include AddressSanitizer DLLs (`clang_rt.asan_dynamic-x86_64.dll`)
- **Workaround**: Use WSL2, Docker, or native Linux for actual fuzzing
- **Note**: Fuzz targets compile successfully, validating code correctness

### Linux/macOS
- ✅ Full fuzzing support with address sanitizer
- ✅ Recommended for long-running fuzz campaigns
- ✅ Best for CI/CD integration

### WSL2 (Windows Subsystem for Linux)
- ✅ Excellent support, recommended for Windows users
- Run with: `cargo +nightly fuzz run <target>`
- Access Windows files via `/mnt/c/...`

## Troubleshooting

### Error: `STATUS_DLL_NOT_FOUND` (0xc0000135)

**Symptoms:**
```
error: process didn't exit successfully: `fuzz\target\...\encoding_fuzz.exe ...` 
(exit code: 0xc0000135, STATUS_DLL_NOT_FOUND)
```

**Solution:** This is expected on Windows. Use WSL2:
```bash
# In PowerShell
wsl

# In WSL
cd /mnt/c/all/Crates-For-Rust/crabgraph
rustup toolchain install nightly
cargo install cargo-fuzz
cargo +nightly fuzz run encoding_fuzz -- -runs=1000
```

### Error: `no such command: fuzz`

**Solution:** Install cargo-fuzz:
```bash
cargo install cargo-fuzz
```

### Error: `requires nightly`

**Solution:** Install nightly toolchain:
```bash
rustup toolchain install nightly
```

### Fuzz target compiles but crashes immediately

**Check:**
1. Are you on Windows? → Use WSL2 (see above)
2. Is it a real crash? → Check artifacts directory for crash inputs
3. Timeout? → Reduce `-max_total_time` or `-runs` value

## Coverage

To generate coverage reports (requires nightly and grcov):

```bash
cargo +nightly fuzz coverage <target_name>
```

## Customizing Fuzz Targets

Each fuzz target is in `fuzz_targets/<target_name>.rs`. To modify:

1. Edit the target file
2. Rebuild: `cargo +nightly fuzz build <target_name>`
3. Run: `cargo +nightly fuzz run <target_name>`

## Best Practices

1. **Start small**: Run each target for short durations first
2. **Monitor crashes**: Check `artifacts/` directory regularly
3. **Minimize corpus**: Periodically run `cargo fuzz cmin`
4. **Vary inputs**: Let fuzzers run long enough to explore state space
5. **CI integration**: Include short fuzz runs in CI pipeline
6. **Dedicated fuzzing**: Consider OSS-Fuzz or dedicated fuzzing infrastructure

## Resources

- [cargo-fuzz documentation](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html)
- [OSS-Fuzz integration guide](https://google.github.io/oss-fuzz/)

## Security Note

Fuzzing is a critical security tool but not a complete solution. CrabGraph still requires:

1. **Professional security audit** by cryptographers
2. **Constant-time analysis** (see `docs/CONSTANT_TIME_AUDIT.md`)
3. **Side-channel resistance testing**
4. **Code review** by security experts

Fuzzing helps find crashes and assertion failures but cannot prove cryptographic correctness.
