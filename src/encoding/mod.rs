//! Encoding and decoding utilities (Base64, Hex).
//!
//! This module provides convenient wrappers around common encoding formats
//! used in cryptography.

use crate::errors::{CrabError, CrabResult};

/// Encodes bytes to base64 string (standard encoding).
///
/// # Example
/// ```
/// use crabgraph::encoding::base64_encode;
///
/// let encoded = base64_encode(b"hello");
/// assert_eq!(encoded, "aGVsbG8=");
/// ```
pub fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Decodes a base64 string to bytes (standard encoding).
///
/// # Errors
/// Returns `CrabError::EncodingError` if the input is not valid base64.
///
/// # Example
/// ```
/// use crabgraph::encoding::base64_decode;
///
/// let decoded = base64_decode("aGVsbG8=").unwrap();
/// assert_eq!(decoded, b"hello");
/// ```
pub fn base64_decode(data: &str) -> CrabResult<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|e| CrabError::encoding_error(format!("Base64 decode failed: {}", e)))
}

/// Encodes bytes to base64 string (URL-safe encoding, no padding).
///
/// This is useful for tokens, URLs, and filenames.
///
/// # Example
/// ```
/// use crabgraph::encoding::base64_url_encode;
///
/// let encoded = base64_url_encode(b"hello");
/// assert!(!encoded.contains('='));
/// ```
pub fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Decodes a URL-safe base64 string to bytes.
///
/// # Errors
/// Returns `CrabError::EncodingError` if the input is not valid base64.
///
/// # Example
/// ```
/// use crabgraph::encoding::{base64_url_encode, base64_url_decode};
///
/// let encoded = base64_url_encode(b"hello");
/// let decoded = base64_url_decode(&encoded).unwrap();
/// assert_eq!(decoded, b"hello");
/// ```
pub fn base64_url_decode(data: &str) -> CrabResult<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|e| CrabError::encoding_error(format!("Base64 URL decode failed: {}", e)))
}

/// Encodes bytes to lowercase hexadecimal string.
///
/// # Example
/// ```
/// use crabgraph::encoding::hex_encode;
///
/// let encoded = hex_encode(b"\x01\x02\xff");
/// assert_eq!(encoded, "0102ff");
/// ```
pub fn hex_encode(data: &[u8]) -> String {
    hex::encode(data)
}

/// Decodes a hexadecimal string to bytes.
///
/// # Errors
/// Returns `CrabError::EncodingError` if the input is not valid hex.
///
/// # Example
/// ```
/// use crabgraph::encoding::hex_decode;
///
/// let decoded = hex_decode("0102ff").unwrap();
/// assert_eq!(decoded, b"\x01\x02\xff");
/// ```
pub fn hex_decode(data: &str) -> CrabResult<Vec<u8>> {
    hex::decode(data)
        .map_err(|e| CrabError::encoding_error(format!("Hex decode failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, World!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64_url_roundtrip() {
        let data = b"Hello, World! 123";
        let encoded = base64_url_encode(data);
        assert!(!encoded.contains('='));
        let decoded = base64_url_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_hex_roundtrip() {
        let data = b"\x00\x01\x02\xfe\xff";
        let encoded = hex_encode(data);
        assert_eq!(encoded, "000102feff");
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64_invalid() {
        let result = base64_decode("not valid base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_hex_invalid() {
        let result = hex_decode("not valid hex");
        assert!(result.is_err());
    }
}
