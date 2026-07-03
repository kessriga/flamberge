use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("crypto error: {0}")]
    Crypto(#[from] flamberge_crypto::CryptoError),

    #[error("invalid input: {0}")]
    Invalid(String),

    #[error("key source not found: {0}")]
    NotFound(String),

    #[error("platform key extraction not supported here: {0}")]
    Unsupported(&'static str),

    #[error("not yet implemented: {0}")]
    Unimplemented(&'static str),
}
