//! Secure random number generation for TLS.

use rustls::crypto::{GetRandomFailed, SecureRandom};

/// Crabgraph's secure random number generator for TLS.
#[derive(Debug)]
pub struct CrabgraphRng;

impl SecureRandom for CrabgraphRng {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        crate::rand::fill_secure_bytes(buf).map_err(|_| GetRandomFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rng_fills_buffer() {
        let rng = CrabgraphRng;
        let mut buf = [0u8; 32];
        rng.fill(&mut buf).unwrap();

        // Very unlikely to be all zeros
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_rng_produces_different_values() {
        let rng = CrabgraphRng;
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];

        rng.fill(&mut buf1).unwrap();
        rng.fill(&mut buf2).unwrap();

        assert_ne!(buf1, buf2);
    }
}
