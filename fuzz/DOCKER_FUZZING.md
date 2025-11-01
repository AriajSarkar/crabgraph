# CrabGraph Fuzzing with Docker

## 🐳 Quick Start

### Run All Fuzz Targets (60 seconds each)

**Old artifacts are automatically cleaned on each run!**

```bash
docker-compose -f docker-compose.fuzz.yml up --build
```

### Manually Clean Artifacts Before Fuzzing (Optional)

```powershell
# Windows
Remove-Item -Path fuzz\artifacts\*\* -Force -ErrorAction SilentlyContinue

# Linux/macOS
rm -rf fuzz/artifacts/*/*
```

### Run Specific Fuzz Target

```bash
# Build the image first
docker-compose -f docker-compose.fuzz.yml build

# Run specific target
docker-compose -f docker-compose.fuzz.yml run fuzz cargo fuzz run aead_fuzz -- -max_total_time=60
docker-compose -f docker-compose.fuzz.yml run fuzz cargo fuzz run ed25519_fuzz -- -max_total_time=60
```

### Available Fuzz Targets

- `aead_fuzz` - AEAD encryption fuzzing
- `ed25519_fuzz` - Ed25519 signing fuzzing
- `encoding_fuzz` - Base64/hex encoding fuzzing
- `hash_fuzz` - Hash function fuzzing
- `kdf_fuzz` - Key derivation fuzzing
- `key_wrap_fuzz` - AES Key Wrap fuzzing
- `mac_fuzz` - HMAC fuzzing
- `stream_fuzz` - Streaming encryption fuzzing
- `x25519_fuzz` - X25519 key exchange fuzzing

## 📦 Docker Image Details

- **Base Image**: `rust:slim` (Debian-based, ~300MB - optimized for sanitizers)
- **Toolchain**: Rust nightly with cargo-fuzz
- **Sanitizers**: AddressSanitizer enabled for better crash detection (requires glibc/dynamic linking)
- **Caching**: 
  - Docker layer caching for faster rebuilds
  - Cargo registry cache (dependencies)
  - Cargo git cache (git dependencies)
  - Target directory cache (compiled artifacts)
  - Fuzzing corpus cache (preserved between runs)
- **Build Optimization**: Dependencies cached in separate layer for 10x faster rebuilds

> **Note**: We use Debian Slim instead of Alpine because AddressSanitizer requires dynamic linking (glibc), which isn't available with Alpine's musl libc.

## 🔍 Check for Crashes

After fuzzing, check for artifacts:

```bash
# List crash artifacts
docker-compose -f docker-compose.fuzz.yml run fuzz find fuzz/artifacts -name "crash-*"

# Reproduce a specific crash
docker-compose -f docker-compose.fuzz.yml run fuzz cargo fuzz run <target> fuzz/artifacts/<target>/crash-*
```

## 🧹 Cleanup

```bash
# Stop and remove containers
docker-compose -f docker-compose.fuzz.yml down

# Remove containers and volumes (WARNING: deletes cached dependencies)
docker-compose -f docker-compose.fuzz.yml down -v

# Remove Docker image
docker rmi crabgraph-fuzz:latest

# Clean specific cache (if needed)
docker volume rm crabgraph-cargo-cache
docker volume rm crabgraph-cargo-git-cache
docker volume rm crabgraph-target-cache
docker volume rm crabgraph-fuzz-corpus
```

## ⚙️ Advanced Usage

### Run with Custom Duration

```bash
docker-compose -f docker-compose.fuzz.yml run fuzz cargo fuzz run aead_fuzz -- -max_total_time=300
```

### Run with More Runs

```bash
docker-compose -f docker-compose.fuzz.yml run fuzz cargo fuzz run aead_fuzz -- -runs=1000000
```

### Build Fuzz Target Only

```bash
docker-compose -f docker-compose.fuzz.yml run fuzz cargo fuzz build aead_fuzz
```

### List All Fuzz Targets

```bash
docker-compose -f docker-compose.fuzz.yml run fuzz cargo fuzz list
```

## 🚀 CI/CD Integration

The Docker setup is also used in GitHub Actions for consistent fuzzing across environments.

## 📊 Understanding Output

```
INFO: Seed: 4024172919
#2995  NEW    cov: 290 ft: 292 corp: 2/34b
```

- **cov**: Code coverage (higher is better)
- **ft**: Feature coverage (unique code paths)
- **corp**: Corpus size (interesting inputs found)
- **exec/s**: Executions per second

## ⚠️ Notes

- Fuzzing is CPU-intensive; monitor system resources
- Each target runs for 60 seconds by default (configurable)
- Crashes are saved to `fuzz/artifacts/<target>/`
- Use volumes to preserve artifacts between runs
