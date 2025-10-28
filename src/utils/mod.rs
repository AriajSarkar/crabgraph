//! Utility functions for cryptographic operations.

use subtle::ConstantTimeEq;

/// Performs constant-time comparison of two byte slices.
///
/// This function uses the `subtle` crate to ensure the comparison takes
/// the same amount of time regardless of where the first difference occurs.
/// This prevents timing attacks that could leak information about secret values.
///
/// **When to use constant-time comparison:**
/// - Comparing authentication tags (HMAC, signatures)
/// - Comparing passwords or password hashes
/// - Comparing encryption keys or derived keys
/// - Any comparison involving secret material
///
/// **When NOT to use (regular `==` is fine):**
/// - Comparing public data (public keys, nonces, IDs)
/// - Comparing lengths or sizes
/// - Non-cryptographic data
///
/// # Example
/// ```
/// use crabgraph::utils::constant_time_eq;
///
/// let secret_a = b"correct_password_hash";
/// let secret_b = b"correct_password_hash";
/// let wrong = b"wrong_password_hash!!";
///
/// assert!(constant_time_eq(secret_a, secret_b));
/// assert!(!constant_time_eq(secret_a, wrong));
/// ```
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    // Use subtle crate's constant-time comparison
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq_equal() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
    }

    #[test]
    fn test_constant_time_eq_not_equal() {
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"hello", b"hello!"));
        assert!(!constant_time_eq(b"", b"x"));
    }

    #[test]
    fn test_constant_time_eq_first_byte_different() {
        assert!(!constant_time_eq(b"abcd", b"xbcd"));
    }

    #[test]
    fn test_constant_time_eq_last_byte_different() {
        assert!(!constant_time_eq(b"abcd", b"abcx"));
    }

    #[test]
    fn test_constant_time_eq_middle_byte_different() {
        assert!(!constant_time_eq(b"abcd", b"abxd"));
    }
}
