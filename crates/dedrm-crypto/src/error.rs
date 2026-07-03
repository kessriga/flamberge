use thiserror::Error;

/// Errors from the crypto primitives.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid key length: expected {expected} bytes, got {got}")]
    KeyLength { expected: usize, got: usize },

    #[error("invalid IV length: expected {expected} bytes, got {got}")]
    IvLength { expected: usize, got: usize },

    #[error("input length {0} is not a multiple of the {1}-byte block size")]
    NotBlockAligned(usize, usize),

    #[error("invalid PKCS#7 padding (wrong key?)")]
    BadPadding,

    #[error("RSA operation failed: {0}")]
    Rsa(String),
}
