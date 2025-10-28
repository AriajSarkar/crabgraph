//! Utility functions for cryptographic operations.

/// Performs constant-time comparison of two byte slices.
///
/// This function is designed to prevent timing attacks by ensuring
/// the comparison takes the same amount of time regardless of where
/// the first difference occurs.
///
/// # Example
/// ```
/// use crabgraph::utils::constant_time_eq;
///
/// let a = b"secret123";
/// let b = b"secret123";
/// let c = b"secret456";
///
/// assert!(constant_time_eq(a, b));
/// assert!(!constant_time_eq(a, c));
/// ```
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
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
