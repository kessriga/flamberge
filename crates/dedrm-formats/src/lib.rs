//! Container/format parsers for the DeDRM schemes.
//!
//! Each module parses one container into structured records but performs **no
//! decryption** — that is the job of `dedrm-schemes`, which combines a parsed
//! container with keys from `dedrm-keys` and ciphers from `dedrm-crypto`.
//!
//! Reference: `docs/DEDRM_SCHEMES.md` (per-scheme container sections).

pub mod error;
pub mod ion;
pub mod kfx_zip;
pub mod mobi;
pub mod ocf;
pub mod palmdb;
pub mod pdf;
pub mod topaz_container;

pub use error::FormatError;

pub type Result<T> = std::result::Result<T, FormatError>;
