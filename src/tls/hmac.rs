//! HMAC, HKDF, and PRF implementations for TLS.

use hmac::{Mac, SimpleHmac};
use rustls::crypto::hmac::{Hmac, Key, Tag};
use rustls::crypto::tls12::Prf;
use rustls::crypto::tls13::{
    Hkdf, HkdfExpander, OkmBlock, OutputLengthError,
};
use sha2::{Sha256, Sha384};

/// HMAC-SHA256 for TLS.
pub static HMAC_SHA256: &dyn Hmac = &HmacSha256;

/// HMAC-SHA384 for TLS.
pub static HMAC_SHA384: &dyn Hmac = &HmacSha384;

// ============================================================================
// HMAC Implementations
// ============================================================================

/// HMAC-SHA256 implementation for TLS.
#[derive(Debug)]
pub struct HmacSha256;

impl Hmac for HmacSha256 {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        Box::new(HmacSha256Key(
            SimpleHmac::<Sha256>::new_from_slice(key).expect("HMAC key should be valid"),
        ))
    }

    fn hash_output_len(&self) -> usize {
        32
    }
}

struct HmacSha256Key(SimpleHmac<Sha256>);

impl Key for HmacSha256Key {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let mut hmac = self.0.clone();
        hmac.update(first);
        for m in middle {
            hmac.update(m);
        }
        hmac.update(last);
        Tag::new(&hmac.finalize().into_bytes()[..])
    }

    fn tag_len(&self) -> usize {
        32
    }
}

/// HMAC-SHA384 implementation for TLS.
#[derive(Debug)]
pub struct HmacSha384;

impl Hmac for HmacSha384 {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        Box::new(HmacSha384Key(
            SimpleHmac::<Sha384>::new_from_slice(key).expect("HMAC key should be valid"),
        ))
    }

    fn hash_output_len(&self) -> usize {
        48
    }
}

struct HmacSha384Key(SimpleHmac<Sha384>);

impl Key for HmacSha384Key {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let mut hmac = self.0.clone();
        hmac.update(first);
        for m in middle {
            hmac.update(m);
        }
        hmac.update(last);
        Tag::new(&hmac.finalize().into_bytes()[..])
    }

    fn tag_len(&self) -> usize {
        48
    }
}

// ============================================================================
// TLS 1.3 HKDF Implementations
// ============================================================================

/// HKDF-SHA256 for TLS 1.3.
#[derive(Debug)]
pub struct HkdfSha256;

impl Hkdf for HkdfSha256 {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn HkdfExpander> {
        let salt = salt.unwrap_or(&[0u8; 32]);
        let (prk, _) = hkdf::Hkdf::<Sha256>::extract(Some(salt), &[0u8; 32]);
        Box::new(HkdfSha256Expander { prk })
    }

    fn extract_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn HkdfExpander> {
        let salt = salt.unwrap_or(&[0u8; 32]);
        let (prk, _) = hkdf::Hkdf::<Sha256>::extract(Some(salt), secret);
        Box::new(HkdfSha256Expander { prk })
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander> {
        // Use the OKM directly as the PRK
        let mut prk = [0u8; 32];
        prk[..okm.as_ref().len().min(32)].copy_from_slice(&okm.as_ref()[..okm.as_ref().len().min(32)]);
        Box::new(HkdfSha256Expander {
            prk: hkdf::hmac::digest::Output::<Sha256>::from(prk),
        })
    }

    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> Tag {
        let mut mac = SimpleHmac::<Sha256>::new_from_slice(key.as_ref())
            .expect("HMAC key should be valid");
        mac.update(message);
        Tag::new(&mac.finalize().into_bytes()[..])
    }

    fn fips(&self) -> bool {
        false // RustCrypto is not FIPS certified
    }
}

struct HkdfSha256Expander {
    prk: hkdf::hmac::digest::Output<Sha256>,
}

impl HkdfExpander for HkdfSha256Expander {
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        let hkdf = hkdf::Hkdf::<Sha256>::from_prk(&self.prk).map_err(|_| OutputLengthError)?;
        let info_concat: Vec<u8> = info.iter().flat_map(|s| s.iter().copied()).collect();
        hkdf.expand(&info_concat, output)
            .map_err(|_| OutputLengthError)
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        let mut output = [0u8; 32];
        let _ = self.expand_slice(info, &mut output);
        OkmBlock::new(&output)
    }

    fn hash_len(&self) -> usize {
        32
    }
}

/// HKDF-SHA384 for TLS 1.3.
#[derive(Debug)]
pub struct HkdfSha384;

impl Hkdf for HkdfSha384 {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn HkdfExpander> {
        let salt = salt.unwrap_or(&[0u8; 48]);
        let (prk, _) = hkdf::Hkdf::<Sha384>::extract(Some(salt), &[0u8; 48]);
        Box::new(HkdfSha384Expander { prk })
    }

    fn extract_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn HkdfExpander> {
        let salt = salt.unwrap_or(&[0u8; 48]);
        let (prk, _) = hkdf::Hkdf::<Sha384>::extract(Some(salt), secret);
        Box::new(HkdfSha384Expander { prk })
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander> {
        let mut prk = [0u8; 48];
        prk[..okm.as_ref().len().min(48)].copy_from_slice(&okm.as_ref()[..okm.as_ref().len().min(48)]);
        Box::new(HkdfSha384Expander {
            prk: hkdf::hmac::digest::Output::<Sha384>::from(prk),
        })
    }

    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> Tag {
        let mut mac = SimpleHmac::<Sha384>::new_from_slice(key.as_ref())
            .expect("HMAC key should be valid");
        mac.update(message);
        Tag::new(&mac.finalize().into_bytes()[..])
    }

    fn fips(&self) -> bool {
        false
    }
}

struct HkdfSha384Expander {
    prk: hkdf::hmac::digest::Output<Sha384>,
}

impl HkdfExpander for HkdfSha384Expander {
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        let hkdf = hkdf::Hkdf::<Sha384>::from_prk(&self.prk).map_err(|_| OutputLengthError)?;
        let info_concat: Vec<u8> = info.iter().flat_map(|s| s.iter().copied()).collect();
        hkdf.expand(&info_concat, output)
            .map_err(|_| OutputLengthError)
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        let mut output = [0u8; 48];
        let _ = self.expand_slice(info, &mut output);
        OkmBlock::new(&output)
    }

    fn hash_len(&self) -> usize {
        48
    }
}

// ============================================================================
// TLS 1.2 PRF Implementations
// ============================================================================

/// TLS 1.2 PRF using SHA-256.
#[derive(Debug)]
pub struct PrfSha256;

impl Prf for PrfSha256 {
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn rustls::crypto::ActiveKeyExchange>,
        peer_pub_key: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), rustls::Error> {
        let shared = kx.complete(peer_pub_key)?;
        self.for_secret(output, shared.secret_bytes(), label, seed);
        Ok(())
    }

    fn for_secret(&self, output: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
        prf_sha256(output, secret, label, seed);
    }

    fn fips(&self) -> bool {
        false
    }
}

/// TLS 1.2 PRF using SHA-384.
#[derive(Debug)]
pub struct PrfSha384;

impl Prf for PrfSha384 {
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn rustls::crypto::ActiveKeyExchange>,
        peer_pub_key: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), rustls::Error> {
        let shared = kx.complete(peer_pub_key)?;
        self.for_secret(output, shared.secret_bytes(), label, seed);
        Ok(())
    }

    fn for_secret(&self, output: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
        prf_sha384(output, secret, label, seed);
    }

    fn fips(&self) -> bool {
        false
    }
}

/// TLS 1.2 P_SHA256 function (RFC 5246).
fn prf_sha256(output: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
    // P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
    //                        HMAC_hash(secret, A(2) + seed) +
    //                        HMAC_hash(secret, A(3) + seed) + ...
    // where A(0) = seed, A(i) = HMAC_hash(secret, A(i-1))

    let mut label_seed = Vec::with_capacity(label.len() + seed.len());
    label_seed.extend_from_slice(label);
    label_seed.extend_from_slice(seed);

    let mut a = {
        let mut mac =
            SimpleHmac::<Sha256>::new_from_slice(secret).expect("HMAC key should be valid");
        mac.update(&label_seed);
        mac.finalize().into_bytes()
    };

    let mut offset = 0;
    while offset < output.len() {
        // P_hash = HMAC(secret, A(i) + seed)
        let mut mac =
            SimpleHmac::<Sha256>::new_from_slice(secret).expect("HMAC key should be valid");
        mac.update(&a);
        mac.update(&label_seed);
        let p = mac.finalize().into_bytes();

        let to_copy = (output.len() - offset).min(32);
        output[offset..offset + to_copy].copy_from_slice(&p[..to_copy]);
        offset += to_copy;

        // A(i+1) = HMAC(secret, A(i))
        let mut mac =
            SimpleHmac::<Sha256>::new_from_slice(secret).expect("HMAC key should be valid");
        mac.update(&a);
        a = mac.finalize().into_bytes();
    }
}

/// TLS 1.2 P_SHA384 function.
fn prf_sha384(output: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
    let mut label_seed = Vec::with_capacity(label.len() + seed.len());
    label_seed.extend_from_slice(label);
    label_seed.extend_from_slice(seed);

    let mut a = {
        let mut mac =
            SimpleHmac::<Sha384>::new_from_slice(secret).expect("HMAC key should be valid");
        mac.update(&label_seed);
        mac.finalize().into_bytes()
    };

    let mut offset = 0;
    while offset < output.len() {
        let mut mac =
            SimpleHmac::<Sha384>::new_from_slice(secret).expect("HMAC key should be valid");
        mac.update(&a);
        mac.update(&label_seed);
        let p = mac.finalize().into_bytes();

        let to_copy = (output.len() - offset).min(48);
        output[offset..offset + to_copy].copy_from_slice(&p[..to_copy]);
        offset += to_copy;

        let mut mac =
            SimpleHmac::<Sha384>::new_from_slice(secret).expect("HMAC key should be valid");
        mac.update(&a);
        a = mac.finalize().into_bytes();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256() {
        let key = HMAC_SHA256.with_key(b"secret key");
        let tag = key.sign_concat(b"hello", &[], b" world");
        assert_eq!(tag.as_ref().len(), 32);
    }

    #[test]
    fn test_hmac_sha384() {
        let key = HMAC_SHA384.with_key(b"secret key");
        let tag = key.sign_concat(b"hello", &[], b" world");
        assert_eq!(tag.as_ref().len(), 48);
    }

    #[test]
    fn test_hmac_consistency() {
        let key1 = HMAC_SHA256.with_key(b"key");
        let key2 = HMAC_SHA256.with_key(b"key");
        
        let tag1 = key1.sign_concat(b"message", &[], b"");
        let tag2 = key2.sign_concat(b"message", &[], b"");
        
        assert_eq!(tag1.as_ref(), tag2.as_ref());
    }

    #[test]
    fn test_hmac_middle_parts() {
        let key = HMAC_SHA256.with_key(b"key");
        
        // These should produce the same result
        let tag1 = key.sign_concat(b"", &[b"hello", b" ", b"world"], b"");
        let tag2 = key.sign_concat(b"hello world", &[], b"");
        
        assert_eq!(tag1.as_ref(), tag2.as_ref());
    }
}
