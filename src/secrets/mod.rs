//! Secure secret handling with automatic memory zeroing.
//!
//! This module provides types that automatically zeroize sensitive data
//! when dropped, preventing secrets from lingering in memory.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A vector that zeroizes its contents on drop.
///
/// Use this type for storing sensitive data like keys, passwords, or
/// plaintext that should not remain in memory after use.
///
/// # Example
/// ```
/// use crabgraph::secrets::SecretVec;
///
/// let mut secret = SecretVec::new(vec![1, 2, 3, 4]);
/// // Use secret...
/// drop(secret); // Memory is automatically zeroized
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretVec(Vec<u8>);

impl SecretVec {
    /// Creates a new `SecretVec` from a byte vector.
    ///
    /// # Example
    /// ```
    /// use crabgraph::secrets::SecretVec;
    ///
    /// let secret = SecretVec::new(vec![1, 2, 3]);
    /// ```
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    /// Creates a new `SecretVec` with the specified capacity.
    ///
    /// # Example
    /// ```
    /// use crabgraph::secrets::SecretVec;
    ///
    /// let mut secret = SecretVec::with_capacity(32);
    /// ```
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    /// Creates a new `SecretVec` filled with zeros.
    ///
    /// # Example
    /// ```
    /// use crabgraph::secrets::SecretVec;
    ///
    /// let secret = SecretVec::zero(32);
    /// assert_eq!(secret.len(), 32);
    /// ```
    pub fn zero(len: usize) -> Self {
        Self(vec![0u8; len])
    }

    /// Returns the length of the secret data.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns a reference to the secret data.
    ///
    /// # Security Note
    /// Be careful not to copy or clone the returned slice, as that would
    /// create unprotected copies in memory.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns a mutable reference to the secret data.
    ///
    /// # Security Note
    /// Any modifications should be careful not to leak the old data.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Consumes the `SecretVec` and returns the inner `Vec<u8>`.
    ///
    /// # Security Warning
    /// The returned `Vec<u8>` is NOT automatically zeroized. Use this only
    /// when you need to pass ownership to another zeroizing container.
    pub fn into_inner(mut self) -> Vec<u8> {
        // We take the inner vec without zeroizing
        // This is intentional for cases where ownership is transferred
        std::mem::take(&mut self.0)
    }

    /// Extends the secret with additional data.
    pub fn extend_from_slice(&mut self, data: &[u8]) {
        self.0.extend_from_slice(data);
    }
}

impl From<Vec<u8>> for SecretVec {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl AsRef<[u8]> for SecretVec {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for SecretVec {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

// Explicitly do NOT implement Debug to prevent accidental logging
impl std::fmt::Debug for SecretVec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretVec([REDACTED {} bytes])", self.0.len())
    }
}

/// A fixed-size array that zeroizes on drop.
///
/// Use this for small secrets with known size at compile time.
///
/// # Example
/// ```
/// use crabgraph::secrets::SecretArray;
///
/// let mut secret = SecretArray::<32>::new([0u8; 32]);
/// // Use secret...
/// drop(secret); // Automatically zeroized
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretArray<const N: usize>([u8; N]);

impl<const N: usize> SecretArray<N> {
    /// Creates a new `SecretArray` from a byte array.
    pub fn new(data: [u8; N]) -> Self {
        Self(data)
    }

    /// Creates a new `SecretArray` filled with zeros.
    pub fn zero() -> Self {
        Self([0u8; N])
    }

    /// Returns a reference to the secret data.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns a mutable reference to the secret data.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Returns the length of the array.
    pub const fn len(&self) -> usize {
        N
    }

    /// Returns `true` if the array length is zero.
    pub const fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<const N: usize> From<[u8; N]> for SecretArray<N> {
    fn from(data: [u8; N]) -> Self {
        Self::new(data)
    }
}

impl<const N: usize> AsRef<[u8]> for SecretArray<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> AsMut<[u8]> for SecretArray<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<const N: usize> std::fmt::Debug for SecretArray<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretArray([REDACTED {} bytes])", N)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_vec_basic() {
        let secret = SecretVec::new(vec![1, 2, 3, 4]);
        assert_eq!(secret.len(), 4);
        assert!(!secret.is_empty());
        assert_eq!(secret.as_slice(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_secret_vec_zero() {
        let secret = SecretVec::zero(32);
        assert_eq!(secret.len(), 32);
        assert_eq!(secret.as_slice(), &[0u8; 32]);
    }

    #[test]
    fn test_secret_vec_debug() {
        let secret = SecretVec::new(vec![1, 2, 3]);
        let debug_str = format!("{:?}", secret);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("1"));
    }

    #[test]
    fn test_secret_array_basic() {
        let secret = SecretArray::new([1, 2, 3, 4]);
        assert_eq!(secret.len(), 4);
        assert_eq!(secret.as_slice(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_secret_array_zero() {
        let secret = SecretArray::<32>::zero();
        assert_eq!(secret.len(), 32);
        assert_eq!(secret.as_slice(), &[0u8; 32]);
    }

    #[test]
    fn test_secret_array_debug() {
        let secret = SecretArray::new([1, 2, 3]);
        let debug_str = format!("{:?}", secret);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("1"));
    }

    #[test]
    fn test_extend_from_slice() {
        let mut secret = SecretVec::new(vec![1, 2]);
        secret.extend_from_slice(&[3, 4]);
        assert_eq!(secret.as_slice(), &[1, 2, 3, 4]);
    }
}
