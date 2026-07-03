//! Shared cryptographic primitives for the Flamberge tool suite.
//!
//! Two ciphers here are bespoke to the ebook-DRM world and are implemented from
//! scratch (they exist in no crate): the **PC1 / Pukall** stream cipher used by
//! Mobipocket, and the **Topaz** stream cipher. Everything else (AES, DES, RC4,
//! digests, PBKDF2) is a thin wrapper over standard implementations.
//!
//! See `docs/DEDRM_SCHEMES.md` §1 for the reference specification.

pub mod aes;
pub mod crc32;
pub mod des;
pub mod digest;
pub mod error;
pub mod kdf;
pub mod pc1;
pub mod rc4;
pub mod topaz;

pub use error::CryptoError;

/// Convenience result alias for this crate.
pub type Result<T> = std::result::Result<T, CryptoError>;
