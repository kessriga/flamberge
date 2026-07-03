use thiserror::Error;

#[derive(Debug, Error)]
pub enum SchemeError {
    #[error("crypto error: {0}")]
    Crypto(#[from] flamberge_crypto::CryptoError),

    #[error("format error: {0}")]
    Format(#[from] flamberge_formats::FormatError),

    #[error("key error: {0}")]
    Key(#[from] flamberge_keys::KeyError),

    /// This file is not handled by the scheme that was tried; move to the next.
    #[error("not this scheme")]
    NotThisScheme,

    #[error("unknown/unsupported format for extension .{0}")]
    UnknownFormat(String),

    #[error("no candidate key decrypted the book")]
    NoKeyWorked,

    /// Mobipocket type-2 book whose DRM voucher block was never initialised
    /// (`drm_count == 0`) — it must be opened in Mobipocket Reader once first.
    #[error("DRM not initialised; open the book in its reader application first")]
    DrmNotInitialised,

    /// Library/rental Mobipocket book (EXTH 406 expiry is nonzero).
    #[error("cannot decode a library or rented ebook (expiry is set)")]
    RentalBook,

    /// Mobipocket record-0 encryption type is neither 0, 1, nor 2.
    #[error("unknown Mobipocket encryption type {0}")]
    UnknownEncryption(u16),

    #[error("not yet implemented: {0}")]
    Unimplemented(&'static str),
}
