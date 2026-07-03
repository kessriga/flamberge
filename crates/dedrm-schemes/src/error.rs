use thiserror::Error;

#[derive(Debug, Error)]
pub enum SchemeError {
    #[error("crypto error: {0}")]
    Crypto(#[from] dedrm_crypto::CryptoError),

    #[error("format error: {0}")]
    Format(#[from] dedrm_formats::FormatError),

    #[error("key error: {0}")]
    Key(#[from] dedrm_keys::KeyError),

    /// This file is not handled by the scheme that was tried; move to the next.
    #[error("not this scheme")]
    NotThisScheme,

    #[error("unknown/unsupported format for extension .{0}")]
    UnknownFormat(String),

    #[error("no candidate key decrypted the book")]
    NoKeyWorked,

    #[error("not yet implemented: {0}")]
    Unimplemented(&'static str),
}
