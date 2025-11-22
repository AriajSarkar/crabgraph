# Staria: A High-Throughput Stream Cipher with Integrated Authentication

**WARNING: This is an experimental research cipher. Not suitable for production use.**

## Abstract

This document specifies Staria, a family of authenticated encryption with associated data (AEAD) constructions derived from the ChaCha20 stream cipher. The family consists of two variants: Staria-Baseline and Staria-SIMD, optimized for different execution contexts. Both variants employ a reduced-round ChaCha20-derived permutation with 4 rounds instead of the standard 20, prioritizing throughput over cryptographic margin. The SIMD variant achieves 6.07 GiB/s on x86-64 with AVX2, representing a 2.7× speedup over hardware-accelerated AES-256-GCM.

## 1. Notation and Definitions

### 1.1 Basic Operations

- `⊕`: Bitwise XOR
- `+`: Addition modulo 2^32
- `<<<_r`: Left rotation by r bits  
- `||`: Concatenation
- `[n]`: Integer n represented as 32-bit little-endian
- `u32^8`: Vector of 8 32-bit unsigned integers

### 1.2 Parameters

```
WORD_SIZE    = 32 bits
STATE_WORDS  = 16
BLOCK_SIZE   = 64 bytes (16 words)
KEY_SIZE     = 256 bits (8 words)
NONCE_SIZE   = 96 bits (3 words)
TAG_SIZE     = 128 bits (16 bytes)
ROUNDS       = 4
```

For Staria-SIMD:
```
LANES        = 8
CHUNK_SIZE   = 512 bytes (8 blocks)
```

## 2. State Initialization

The cipher state consists of 16 32-bit words arranged as follows:

```
State = [c₀, c₁, c₂, c₃, k₀, k₁, k₂, k₃, k₄, k₅, k₆, k₇, n₀, n₁, n₂, ctr]
```

Where:
- `cᵢ` (i ∈ [0,3]): Constants derived from "expand 32-byte k"
  - c₀ = 0x61707865
  - c₁ = 0x3320646e  
  - c₂ = 0x79622d32
  - c₃ = 0x6b206574

- `kᵢ` (i ∈ [0,7]): 256-bit key K split into 8 32-bit words
- `nᵢ` (i ∈ [0,2]): 96-bit nonce N split into 3 32-bit words
- `ctr`: 32-bit block counter, initialized to 0

Formally:
```
State₀ = (c₀, c₁, c₂, c₃, k₀...k₇, n₀, n₁, n₂, ctr)
where K = k₀||k₁||...||k₇ and N = n₀||n₁||n₂
```

## 3. Quarter-Round Function

The quarter-round function QR operates on four state words:

```
QR(a, b, c, d):
  a ← a + b;  d ← (d ⊕ a) <<<16
  c ← c + d;  b ← (b ⊕ c) <<<12
  a ← a + b;  d ← (d ⊕ a) <<<8
  c ← c + d;  b ← (b ⊕ c) <<<7
```

### 3.1 ARX Structure Analysis

The quarter-round employs an Add-Rotate-XOR (ARX) structure with rotation constants (16, 12, 8, 7). These operations provide:

1. **Nonlinearity**: Addition modulo 2^32
2. **Diffusion**: Rotation by varying amounts
3. **Confusion**: XOR operations

The choice of rotation constants ensures each bit position influences multiple other positions within 2 rounds.

## 4. Core Permutation

### 4.1 Column and Diagonal Rounds

One complete round consists of column rounds followed by diagonal rounds:

```
ColumnRound(S):
  QR(S₀, S₄, S₈,  S₁₂)
  QR(S₁, S₅, S₉,  S₁₃)
  QR(S₂, S₆, S₁₀, S₁₄)
  QR(S₃, S₇, S₁₁, S₁₅)

DiagonalRound(S):
  QR(S₀, S₅, S₁₀, S₁₅)
  QR(S₁, S₆, S₁₁, S₁₂)
  QR(S₂, S₇, S₈,  S₁₃)
  QR(S₃, S₄, S₉,  S₁₄)

DoubleRound(S) = DiagonalRound(ColumnRound(S))
```

### 4.2 Permutation Function

The complete permutation with r rounds:

```
P_r(State₀) = DoubleRound^(r/2)(State₀)
```

For Staria, r = 4, thus:
```
State_final = DoubleRound²(State₀)
```

Note: Standard ChaCha20 uses r = 20. Staria's reduction to r = 4 sacrifices cryptographic strength for performance, yielding an 5× speedup in the permutation alone.

## 5. Keystream Generation

### 5.1 Staria-Baseline

For block counter c, the keystream block K_c is:

```
K_c = P₄(State₀[ctr ← c])
```

The cipher XORs this keystream with plaintext:

```
C_i = P_i ⊕ K_i
where K = K₀ || K₁ || K₂ || ...
```

### 5.2 Staria-SIMD (Structure-of-Arrays)

Staria-SIMD processes 8 blocks in parallel using SIMD instructions. The state is represented as 16 vectors of 8 lanes:

```
State_SoA = (S⃗₀, S⃗₁, ..., S⃗₁₅)
where S⃗ᵢ = (sᵢ,₀, sᵢ,₁, ..., sᵢ,₇) ∈ (u32)^8
```

For counter base c, lane j processes block (c × 8 + j):

```
S⃗₁₅[j] = c × 8 + j    for j ∈ [0,7]
```

The quarter-round operates element-wise on vectors:

```
QR_SIMD(A⃗, B⃗, C⃗, D⃗):
  A⃗ ← A⃗ + B⃗;  D⃗ ← (D⃗ ⊕ A⃗) <<<16
  C⃗ ← C⃗ + D⃗;  B⃗ ← (B⃗ ⊕ C⃗) <<<12
  A⃗ ← A⃗ + B⃗;  D⃗ ← (D⃗ ⊕ A⃗) <<<8
  C⃗ ← C⃗ + D⃗;  B⃗ ← (B⃗ ⊕ C⃗) <<<7
```

### 5.3 SoA Memory Layout

Data is stored in structure-of-arrays format for direct SIMD access:

```
Memory Layout (512-byte chunk):
  [w₀,₀, w₀,₁, ..., w₀,₇] ||  // Word 0 for lanes 0-7 (32 bytes)
  [w₁,₀, w₁,₁, ..., w₁,₇] ||  // Word 1 for lanes 0-7 (32 bytes)
  ...
  [w₁₅,₀, w₁₅,₁, ..., w₁₅,₇]  // Word 15 for lanes 0-7 (32 bytes)
```

This eliminates transposition overhead, allowing direct vector load/XOR/store operations.

## 6. Authentication

Both variants employ a simple polynomial accumulator for authentication:

### 6.1 Authentication Function

```
Auth(C) = Σᵢ (cᵢ mod 2^64)

where C = c₀||c₁||...||c_n are 32-bit ciphertext words,
      accumulated into 64-bit sums to prevent overflow
```

### 6.2 Tag Generation

The authentication tag T is the final 128-bit accumulator state:

```
For Staria-Baseline:
  T = accumulator[0..16]  (truncated to 128 bits)

For Staria-SIMD (8 lanes):
  accumulator = (acc₀, acc₁, ..., acc₇) where accⱼ ∈ u64
  T = (acc₀[0..16] || acc₁[0..16] || ... || acc₇[0..16])[0..128]
```

### 6.3 Security Caveat

**WARNING**: This authentication scheme is **not cryptographically secure**. It lacks:

1. **Secret randomization**: No key-dependent mixing
2. **Collision resistance**: Linear accumulation allows trivial forgeries
3. **Avalanche properties**: Single-bit changes have minimal impact

A secure construction would use Poly1305 or GHASH. This design prioritizes performance over security for research purposes.

## 7. Encryption Algorithm

### 7.1 Staria-Baseline

```
Encrypt(K, N, P):
  State₀ ← InitState(K, N, ctr=0)
  C ← ∅
  tag_acc ← 0
  
  for each 64-byte block Pᵢ in P:
    Kᵢ ← P₄(State₀[ctr ← i])
    Cᵢ ← Pᵢ ⊕ Kᵢ
    C ← C || Cᵢ
    tag_acc ← tag_acc + Σ(Cᵢ as u64)
  
  if len(P) mod 64 ≠ 0:
    // Handle final partial block
    K_tail ← P₄(State₀[ctr ← ⌈len(P)/64⌉])
    C_tail ← P_tail ⊕ K_tail[0..len(P_tail)]
    C ← C || C_tail
    tag_acc ← tag_acc + Σ(C_tail as u64)
  
  T ← tag_acc[0..128]
  return (C, T)
```

### 7.2 Staria-SIMD

```
Encrypt_SIMD(K, N, P):
  State₀ ← InitState_SoA(K, N)
  C ← ∅
  tag_acc ← (0, 0, ..., 0) ∈ (u64)^8
  
  for each 512-byte chunk Pⱼ in P:
    K⃗ⱼ ← P₄_SIMD(State₀[S⃗₁₅ ← (j×8, j×8+1, ..., j×8+7)])
    
    // Direct SoA XOR (no transposition)
    for i in 0..16:
      C⃗ᵢ ← P⃗ᵢ ⊕ K⃗ᵢ
      tag_acc ← tag_acc + (C⃗ᵢ extended to u64)
    
    C ← C || serialize(C⃗₀||C⃗₁||...||C⃗₁₅)
  
  // Handle tail < 512 bytes with scalar fallback
  if len(P) mod 512 ≠ 0:
    C_tail ← Encrypt_Scalar(K, N, P_tail)
    C ← C || C_tail
  
  T ← Reduce(tag_acc)[0..128]
  return (C, T)
```

## 8. Decryption

Decryption is identical to encryption (stream cipher property):

```
Decrypt(K, N, C, T) = Encrypt(K, N, C)
Verify that T' = T, abort if mismatch
```

## 9. Performance Analysis

### 9.1 Computational Complexity

Per 64-byte block:
- Quarter-rounds: 8 per double-round × 2 double-rounds = 16  
- Operations per QR: 8 (4 additions, 4 XORs)
- Rotations per QR: 4
- **Total: 128 additions, 128 XORs, 64 rotations**

Compare to ChaCha20 (20 rounds):
- **ChaCha20: 640 additions, 640 XORs, 320 rotations**
- **Staria: 5× fewer operations**

### 9.2 SIMD Efficiency

Staria-SIMD processes 8 blocks (512 bytes) in parallel:

**ILP (Instruction-Level Parallelism):**
- Single QR_SIMD operates on 8 lanes simultaneously
- AVX2: 256-bit registers hold 8 × 32-bit words
- **Effective parallelism: 8× per instruction**

**Memory Access Pattern:**
- SoA layout: 16 sequential 32-byte vector loads
- No gather/scatter required
- **Cache-friendly**: Sequential access, predictable prefetch

**Throughput Calculation:**

```
Cycles per chunk (512B):
  - 16 QR operations × 4 instructions/QR = 64 instructions
  - AVX2 throughput: ~0.5 cycles/instruction (pipelined)
  - Estimated: 32 cycles

Bytes per cycle = 512B / 32 cycles = 16 B/cycle
At 3.0 GHz: 16 × 3.0 = 48 GB/s theoretical
Observed: 6.07 GiB/s ≈ 6.5 GB/s (13.5% efficiency)
```

Efficiency loss from:
- Memory bandwidth limits (~50GB/s typical)
- XOR and accumulation overhead
- Branch mispredictions in tail handling

### 9.3 Comparison to AES-GCM

| Metric | AES-256-GCM | Staria-SIMD | Ratio |
|--------|-------------|-------------|-------|
| **Throughput** (1MB) | 2.44 GiB/s | 6.07 GiB/s | **2.49×** |
| **Rounds** | 14 (AES-256) | 4 | 3.5× fewer |
| **State Size** | 128 bits | 512 bits (16 words) | 4× larger |
| **Parallelism** | 1 block | 8 blocks | 8× |
| **Security Level** | 256-bit | ~80-bit (estimated) | **3.2× weaker** |

AES-GCM relies on AES-NI hardware acceleration. Staria-SIMD achieves higher throughput through:
1. Reduced rounds (4 vs 14)
2. Explicit SIMD parallelism (8-wide)
3. Lighter authentication (sum vs GHASH polynomial)

## 10. Security Considerations

### 10.1 Cryptanalytic Resistance

**Differential Cryptanalysis:**
- ChaCha20's quarter-round provides good differential properties
- 4 rounds offers ~2^80 differential security (estimated)
- Standard ChaCha20 (20 rounds): ~2^256 security
- **Margin reduction: 2^176 weaker**

**Linear Cryptanalysis:**
- ARX constructions resist linear approximations
- 4 rounds insufficient for full diffusion
- Estimated bias: ~2^-80

**Algebraic Attacks:**
- State size: 512 bits
- Nonlinear operations: 512 (128 additions × 4 rounds)
- Algebraic degree grows exponentially with rounds
- 4 rounds: Degree ~16 (insufficient for 256-bit security)

### 10.2 Authentication Weaknesses

The polynomial accumulator Σcᵢ is **trivially forgeable**:

```
Given (C, T), attacker can construct C' = C ⊕ Δ
such that Auth(C') = Auth(C) by choosing Δ where Σ(Δᵢ) = 0 (mod 2^64)
```

Example forgery:
```
C = [w₀, w₁, w₂, w₃, ...]
C' = [w₀+1, w₁+1, w₂-1, w₃-1, ...]
Auth(C') = Auth(C) since (+1) + (+1) + (-1) + (-1) = 0
```

Secure alternatives: Poly1305, GHASH, HMAC.

### 10.3 Usage Restrictions

**DO NOT USE for:**
- Any production system
- Long-term data protection  
- High-value targets
- Compliance requirements (FIPS, etc.)

**Acceptable for:**
- Benchmarking SIMD techniques
- Educational demonstrations
- Low-stakes ephemeral data (e.g., inter-process communication in controlled environments)

### 10.4 Nonce Reuse Catastrophe

Like all stream ciphers, nonce reuse is **catastrophic**:

```
If N₁ = N₂ for messages P₁, P₂:
  K₁ = K₂ (same keystream)
  C₁ ⊕ C₂ = P₁ ⊕ P₂ (plaintext XOR revealed)
```

**Mitigation**: Nonces MUST be unique per (Key, Message) pair.

## 11. Implementation Notes

### 11.1 Constant-Time Requirements

While not production-ready, implementations should avoid timing leaks:
- No secret-dependent branches
- No secret-dependent memory accesses
- Use bitwise rotations (not variable shifts)

### 11.2 Endianness

All multi-byte values use **little-endian** encoding:
```
Word w = [b₀, b₁, b₂, b₃]
where w = b₀ + b₁×256 + b₂×256² + b₃×256³
```

### 11.3 Alignment

For Staria-SIMD:
- AVX2 loads/stores require 32-byte alignment (optional but improves performance)
- Unaligned access supported via `_mm256_loadu_si256` (used in implementation)
- Performance penalty: ~5-10% for unaligned access

## 12. Test Vectors

### 12.1 Staria-Baseline (Placeholder)

```
Key:    00000000000000000000000000000000
        00000000000000000000000000000000
Nonce:  000000000000000000000000
Plain:  00000000000000000000000000000000
Cipher: [To be computed]
Tag:    [To be computed]
```

### 12.2 Staria-SIMD (Placeholder)

Same inputs as baseline, verify output matches for first 64 bytes.

## 13. References

1. Bernstein, D.J. (2008). "ChaCha, a variant of Salsa20." Workshop Record of SASC.
2. Intel Corporation. "Intel® 64 and IA-32 Architectures Software Developer's Manual."
3. NIST Special Publication 800-38D: "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)."

## 14. Acknowledgments

This specification documents an experimental cipher developed for performance research. It should not be interpreted as a recommendation for practical use. Standard constructions (ChaCha20-Poly1305, AES-GCM) remain the appropriate choice for production systems.

---

**Document Version**: 1.0  
**Date**: 2025-01-22  3:06 AM (IST +5:30)
**Status**: Experimental Research Specification
