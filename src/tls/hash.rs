//! Hash algorithm implementations for TLS.

use rustls::crypto::hash::{Context, Hash, HashAlgorithm, Output};
use sha2::{Digest, Sha256, Sha384, Sha512};

/// SHA-256 hash algorithm for TLS.
pub static SHA256: &dyn Hash = &Sha256Hash;

/// SHA-384 hash algorithm for TLS.
pub static SHA384: &dyn Hash = &Sha384Hash;

/// SHA-512 hash algorithm for TLS.
pub static SHA512: &dyn Hash = &Sha512Hash;

/// SHA-256 hash implementation (public for cipher suite definitions).
#[derive(Debug)]
pub struct Sha256Hash;

/// SHA-384 hash implementation (public for cipher suite definitions).
#[derive(Debug)]
pub struct Sha384Hash;

/// SHA-512 hash implementation (public for cipher suite definitions).
#[derive(Debug)]
pub struct Sha512Hash;

impl Hash for Sha256Hash {
    fn start(&self) -> Box<dyn Context> {
        Box::new(Sha256Context(Sha256::new()))
    }

    fn hash(&self, data: &[u8]) -> Output {
        Output::new(&crate::hash::sha256(data)[..])
    }

    fn output_len(&self) -> usize {
        32
    }

    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }
}

#[derive(Debug)]
struct Sha256Context(Sha256);

impl Context for Sha256Context {
    fn fork_finish(&self) -> Output {
        Output::new(&self.0.clone().finalize()[..])
    }

    fn fork(&self) -> Box<dyn Context> {
        Box::new(Sha256Context(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> Output {
        Output::new(&self.0.finalize()[..])
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

impl Hash for Sha384Hash {
    fn start(&self) -> Box<dyn Context> {
        Box::new(Sha384Context(Sha384::new()))
    }

    fn hash(&self, data: &[u8]) -> Output {
        Output::new(&crate::hash::sha384(data)[..])
    }

    fn output_len(&self) -> usize {
        48
    }

    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA384
    }
}

#[derive(Debug)]
struct Sha384Context(Sha384);

impl Context for Sha384Context {
    fn fork_finish(&self) -> Output {
        Output::new(&self.0.clone().finalize()[..])
    }

    fn fork(&self) -> Box<dyn Context> {
        Box::new(Sha384Context(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> Output {
        Output::new(&self.0.finalize()[..])
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

impl Hash for Sha512Hash {
    fn start(&self) -> Box<dyn Context> {
        Box::new(Sha512Context(Sha512::new()))
    }

    fn hash(&self, data: &[u8]) -> Output {
        Output::new(&crate::hash::sha512(data)[..])
    }

    fn output_len(&self) -> usize {
        64
    }

    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA512
    }
}

#[derive(Debug)]
struct Sha512Context(Sha512);

impl Context for Sha512Context {
    fn fork_finish(&self) -> Output {
        Output::new(&self.0.clone().finalize()[..])
    }

    fn fork(&self) -> Box<dyn Context> {
        Box::new(Sha512Context(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> Output {
        Output::new(&self.0.finalize()[..])
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hash() {
        let result = SHA256.hash(b"hello");
        assert_eq!(result.as_ref().len(), 32);
    }

    #[test]
    fn test_sha384_hash() {
        let result = SHA384.hash(b"hello");
        assert_eq!(result.as_ref().len(), 48);
    }

    #[test]
    fn test_sha512_hash() {
        let result = SHA512.hash(b"hello");
        assert_eq!(result.as_ref().len(), 64);
    }

    #[test]
    fn test_sha256_context() {
        let mut ctx = SHA256.start();
        ctx.update(b"hello");
        ctx.update(b" world");
        let result = ctx.finish();

        let direct = SHA256.hash(b"hello world");
        assert_eq!(result.as_ref(), direct.as_ref());
    }

    #[test]
    fn test_context_fork() {
        let mut ctx = SHA256.start();
        ctx.update(b"hello");

        let forked = ctx.fork();
        ctx.update(b" world");

        let result1 = ctx.finish();
        let result2 = forked.finish();

        // Forked context doesn't see " world"
        assert_ne!(result1.as_ref(), result2.as_ref());
    }
}
