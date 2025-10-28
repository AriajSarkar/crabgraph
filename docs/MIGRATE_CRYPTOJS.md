# Migrating from CryptoJS to CrabGraph

This guide helps you migrate from JavaScript's CryptoJS library to CrabGraph (Rust) or use secure alternatives.

## ⚠️ CryptoJS Security Issues

**CryptoJS has several security issues with its default settings:**

1. **Uses MD5 for key derivation** (broken, easily attacked)
2. **Default iteration count is 1** (provides no protection)
3. **Uses AES-CBC without proper authentication** (vulnerable to padding oracle attacks)
4. **Sometimes omits salt** (enables rainbow table attacks)

## Recommended Migration Path

### Option 1: Modernize Your JavaScript Code

Instead of CryptoJS, use the **Web Crypto API** (built into modern browsers):

```javascript
// Modern approach: Web Crypto API with AES-GCM
async function encryptModern(plaintext, password) {
    // Derive key using PBKDF2 (secure)
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        'PBKDF2',
        false,
        ['deriveKey']
    );

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 600000,  // Secure iteration count
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );

    // Encrypt with AES-GCM (authenticated encryption)
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        enc.encode(plaintext)
    );

    // Return salt, IV, and ciphertext
    return {
        salt: Array.from(salt),
        iv: Array.from(iv),
        ciphertext: Array.from(new Uint8Array(ciphertext))
    };
}

async function decryptModern(encrypted, password) {
    const enc = new TextEncoder();
    const dec = new TextDecoder();

    // Derive same key
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        'PBKDF2',
        false,
        ['deriveKey']
    );

    const key = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: new Uint8Array(encrypted.salt),
            iterations: 600000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );

    // Decrypt
    const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(encrypted.iv) },
        key,
        new Uint8Array(encrypted.ciphertext)
    );

    return dec.decode(plaintext);
}
```

### Option 2: Use CrabGraph in Rust

If you're building a Rust backend or using WASM:

```rust
use crabgraph::{
    aead::{AesGcm256, CrabAead},
    kdf::pbkdf2_derive_sha256,
    rand::secure_bytes,
    CrabResult,
};

fn encrypt_with_password(plaintext: &[u8], password: &[u8]) -> CrabResult<Vec<u8>> {
    // Generate random salt
    let salt = secure_bytes(16)?;

    // Derive key using PBKDF2 with secure iteration count
    let key = pbkdf2_derive_sha256(password, &salt, 600_000, 32)?;

    // Encrypt with AES-256-GCM
    let cipher = AesGcm256::new(key.as_slice())?;
    let ciphertext = cipher.encrypt(plaintext, None)?;

    // Serialize: salt || nonce || ciphertext || tag
    let mut result = salt.clone();
    result.extend_from_slice(&ciphertext.to_bytes());

    Ok(result)
}

fn decrypt_with_password(data: &[u8], password: &[u8]) -> CrabResult<Vec<u8>> {
    // Extract salt (first 16 bytes)
    let salt = &data[..16];
    let encrypted = &data[16..];

    // Derive same key
    let key = pbkdf2_derive_sha256(password, salt, 600_000, 32)?;

    // Decrypt
    let cipher = AesGcm256::new(key.as_slice())?;
    let ciphertext = crabgraph::aead::Ciphertext::from_bytes(encrypted, 12, 16)?;
    let plaintext = cipher.decrypt(&ciphertext, None)?;

    Ok(plaintext)
}
```

## Comparison: CryptoJS vs. CrabGraph

| Feature | CryptoJS (default) | CrabGraph |
|---------|-------------------|-----------|
| **Encryption** | AES-CBC | AES-GCM |
| **Authentication** | None | Built-in (AEAD) |
| **Key Derivation** | MD5 | PBKDF2-SHA256 / Argon2 |
| **Iterations** | 1 | 600,000+ |
| **Salt** | Optional | Required (16+ bytes) |
| **Nonce Management** | Manual | Automatic |
| **Memory Safety** | N/A | Zeroization |

## Step-by-Step Migration

### 1. Identify CryptoJS Usage

Look for code like:
```javascript
var encrypted = CryptoJS.AES.encrypt(message, password);
var decrypted = CryptoJS.AES.decrypt(encrypted, password);
```

### 2. Update to Secure Parameters

If you must keep using CryptoJS temporarily:

```javascript
const CryptoJS = require("crypto-js");

// At minimum, fix these issues:
const iterations = 100000;  // Increase from 1
const keySize = 256;
const salt = CryptoJS.lib.WordArray.random(128/8);

const key = CryptoJS.PBKDF2(password, salt, {
    keySize: keySize/32,
    iterations: iterations,
    hasher: CryptoJS.algo.SHA256  // Don't use MD5!
});

const iv = CryptoJS.lib.WordArray.random(128/8);
const encrypted = CryptoJS.AES.encrypt(plaintext, key, { 
    iv: iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
});

// Store: salt, iv, ciphertext
```

### 3. Plan Full Migration

- **Phase 1**: Update iteration counts and use SHA-256
- **Phase 2**: Implement proper salt generation and storage
- **Phase 3**: Migrate to Web Crypto API or CrabGraph
- **Phase 4**: Re-encrypt all stored data with new method

## Interoperability Example

If you need to read CryptoJS-encrypted data in Rust:

```rust
// NOTE: This is for migration only!
// Do not use this for new encryption.

// You'll need to implement CBC mode and PKCS7 padding
// (not included in CrabGraph's high-level API for security reasons)

// Instead, we recommend re-encrypting data:
// 1. Decrypt with CryptoJS (JavaScript)
// 2. Re-encrypt with Web Crypto API or CrabGraph
// 3. Store new format
```

## Security Checklist

When migrating, ensure:

- ✅ Use AES-GCM instead of AES-CBC
- ✅ Use PBKDF2 with ≥600,000 iterations (or Argon2)
- ✅ Generate random salts (≥16 bytes) for each encryption
- ✅ Store salt alongside ciphertext (it's not secret)
- ✅ Use SHA-256 or SHA-512, never MD5 or SHA-1
- ✅ Never reuse nonces/IVs with the same key
- ✅ Verify authentication tags before using decrypted data

## Need Help?

- Check our [examples](../examples/)
- See [SECURITY.md](../SECURITY.md) for security considerations
- Open an issue on GitHub
- Email: ariajsarkar@gmail.com

## References

- [Web Crypto API Documentation](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST SP 800-132: PBKDF2](https://csrc.nist.gov/publications/detail/sp/800-132/final)
