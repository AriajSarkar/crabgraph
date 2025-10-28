//! Key Derivation Functions (KDFs).
//!
//! This module provides password-based and extract-expand KDFs.

pub mod argon2;
pub mod hkdf;
pub mod pbkdf2;

pub use self::argon2::{argon2_derive, argon2_derive_with_params, Argon2Params};
pub use self::hkdf::{hkdf_extract_expand, hkdf_sha256};
pub use self::pbkdf2::{
    pbkdf2_derive, pbkdf2_derive_sha256, pbkdf2_derive_sha512,
    PBKDF2_SHA256_RECOMMENDED_ITERATIONS, PBKDF2_SHA512_RECOMMENDED_ITERATIONS,
};
