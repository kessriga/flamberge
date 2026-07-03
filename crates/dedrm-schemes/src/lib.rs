//! Per-scheme DRM removal. Each module combines a parsed container
//! (`dedrm-formats`), candidate keys (`dedrm-keys`), and ciphers
//! (`dedrm-crypto`) to produce a decrypted book.
//!
//! Reference: `docs/DEDRM_SCHEMES.md`.

pub mod adept;
pub mod ereader;
pub mod error;
pub mod ignoble;
pub mod kfx;
pub mod kobo;
pub mod mobipocket;
pub mod topaz;

pub use dedrm_keys::KeyStore;
pub use error::SchemeError;

pub type Result<T> = std::result::Result<T, SchemeError>;

/// A decrypted book ready to be written out.
#[derive(Debug, Clone)]
pub struct DecryptedBook {
    pub data: Vec<u8>,
    /// Output file extension without the dot (e.g. `mobi`, `epub`, `pdf`).
    pub extension: String,
}

/// The DRM schemes this tool can (eventually) remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Mobipocket,
    Topaz,
    Kfx,
    AdeptEpub,
    IgnobleEpub,
    AdeptPdf,
    IgnoblePdf,
    EReader,
    Kobo,
}

/// Candidate schemes to try for a given file extension, in priority order.
/// Kindle-family files disambiguate further by magic inside the handler.
///
/// Mirrors `DeDRM_plugin/__init__.py::run` extension routing.
pub fn candidates_for_extension(ext: &str) -> &'static [Scheme] {
    match ext.trim_start_matches('.').to_ascii_lowercase().as_str() {
        "prc" | "mobi" | "pobi" | "azw" | "azw1" | "azw3" | "azw4" | "tpz" | "kfx-zip" => {
            &[Scheme::Mobipocket, Scheme::Topaz, Scheme::Kfx]
        }
        "pdb" => &[Scheme::EReader],
        "pdf" => &[Scheme::IgnoblePdf, Scheme::AdeptPdf],
        "epub" => &[Scheme::IgnobleEpub, Scheme::AdeptEpub],
        "kepub" => &[Scheme::Kobo],
        _ => &[],
    }
}

/// Refine a Kindle-family choice by container magic (see
/// `k4mobidedrm.py::GetDecryptedBook`).
pub fn kindle_scheme_from_magic(data: &[u8]) -> Option<Scheme> {
    if data.starts_with(b"\xeaDRMION\xee") {
        // A bare DRMION cannot be decrypted on its own.
        None
    } else if data.starts_with(b"PK\x03\x04") {
        Some(Scheme::Kfx)
    } else if data.starts_with(b"TPZ") {
        Some(Scheme::Topaz)
    } else {
        Some(Scheme::Mobipocket)
    }
}

/// Decrypt `input` given its file extension and a key store, trying each
/// candidate scheme until one succeeds.
pub fn decrypt(input: &[u8], ext: &str, keys: &KeyStore) -> Result<DecryptedBook> {
    let candidates = candidates_for_extension(ext);
    if candidates.is_empty() {
        return Err(SchemeError::UnknownFormat(ext.to_string()));
    }

    let mut last_err = None;
    for &scheme in candidates {
        let result = match scheme {
            Scheme::Mobipocket => mobipocket::decrypt(input, keys),
            Scheme::Topaz => topaz::decrypt(input, keys),
            Scheme::Kfx => kfx::decrypt(input, keys),
            Scheme::AdeptEpub => adept::decrypt_epub(input, keys),
            Scheme::IgnobleEpub => ignoble::decrypt_epub(input, keys),
            Scheme::AdeptPdf => adept::decrypt_pdf(input, keys),
            Scheme::IgnoblePdf => ignoble::decrypt_pdf(input, keys),
            Scheme::EReader => ereader::decrypt(input, keys),
            Scheme::Kobo => kobo::decrypt(input, keys),
        };
        match result {
            Ok(book) => return Ok(book),
            Err(SchemeError::NotThisScheme) => continue,
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or(SchemeError::NoKeyWorked))
}
