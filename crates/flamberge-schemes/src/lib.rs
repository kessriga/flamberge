//! Per-scheme DRM removal. Each module combines a parsed container
//! (`flamberge-formats`), candidate keys (`flamberge-keys`), and ciphers
//! (`flamberge-crypto`) to produce a decrypted book.
//!
//! Reference: `docs/DEDRM_SCHEMES.md`.

pub mod adept;
mod epub_common;
pub mod ereader;
pub mod error;
pub mod ignoble;
pub mod kfx;
pub mod kobo;
pub mod mobipocket;
mod pdf_common;
pub mod topaz;

pub use error::SchemeError;
pub use flamberge_keys::KeyStore;

pub type Result<T> = std::result::Result<T, SchemeError>;

/// A decrypted book ready to be written out.
#[derive(Debug, Clone)]
pub struct DecryptedBook {
    pub data: Vec<u8>,
    /// Output file extension without the dot (e.g. `mobi`, `epub`, `pdf`).
    pub extension: String,
    /// The book's display title, when the scheme can recover it. Used by the
    /// CLI for title-based output naming; `None` when unavailable.
    pub title: Option<String>,
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
    let mut candidates = candidates_for_extension(ext).to_vec();

    // Real Kobo books are named `*.kepub.epub` (extension `epub`) or an
    // extension-less volume id, so they would otherwise route to the EPUB
    // schemes — or nowhere — and never reach the Kobo handler. A supplied Kobo
    // DB is the unambiguous "this is a Kobo book" signal, so for a ZIP input we
    // append Kobo as a fallback candidate (tried after any EPUB schemes, and not
    // for Kindle-family archives like `.kfx-zip`, which have their own routing).
    let is_zip = input.starts_with(b"PK\x03\x04");
    let is_kindle_family = candidates
        .iter()
        .any(|s| matches!(s, Scheme::Mobipocket | Scheme::Topaz | Scheme::Kfx));
    if keys.kobo_db.is_some() && is_zip && !is_kindle_family && !candidates.contains(&Scheme::Kobo)
    {
        candidates.push(Scheme::Kobo);
    }

    if candidates.is_empty() {
        return Err(SchemeError::UnknownFormat(ext.to_string()));
    }

    for scheme in candidates {
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
        // `NotThisScheme` is the only "keep looking" signal: it means the file
        // isn't handled by this scheme. Any other error means the scheme claimed
        // the file (right magic/structure) but decryption failed — that verdict
        // is terminal and must not be masked by a later candidate's error.
        match result {
            Ok(book) => return Ok(book),
            Err(SchemeError::NotThisScheme) => continue,
            Err(e) => return Err(e),
        }
    }
    // No candidate recognized the file.
    Err(SchemeError::NoKeyWorked)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_routing_matches_plugin() {
        assert_eq!(candidates_for_extension("mobi").len(), 3);
        assert_eq!(candidates_for_extension(".AZW3").len(), 3); // dotted + upper-case
        assert_eq!(candidates_for_extension("pdb"), &[Scheme::EReader]);
        assert_eq!(
            candidates_for_extension("pdf"),
            &[Scheme::IgnoblePdf, Scheme::AdeptPdf]
        );
        assert_eq!(
            candidates_for_extension("epub"),
            &[Scheme::IgnobleEpub, Scheme::AdeptEpub]
        );
        assert_eq!(candidates_for_extension("kepub"), &[Scheme::Kobo]);
        assert!(candidates_for_extension("txt").is_empty());
    }

    #[test]
    fn unknown_extension_is_reported() {
        let keys = KeyStore::new();
        match decrypt(b"whatever", "txt", &keys) {
            Err(SchemeError::UnknownFormat(ext)) => assert_eq!(ext, "txt"),
            other => panic!("expected UnknownFormat, got {other:?}"),
        }
    }

    #[test]
    fn all_candidates_falling_through_yields_no_key_worked() {
        // A non-ZIP buffer is not an EPUB, so both EPUB candidates return
        // `NotThisScheme`; dispatch must exhaust them and report `NoKeyWorked`
        // rather than surfacing an internal error from the last candidate tried.
        let keys = KeyStore::new();
        assert!(matches!(
            decrypt(b"definitely not a zip", "epub", &keys),
            Err(SchemeError::NoKeyWorked)
        ));
    }

    #[test]
    fn terminal_error_is_surfaced_not_masked() {
        // A scheme that claims the file but fails must have its error propagated
        // verbatim (not collapsed to `NoKeyWorked`). `.pdb` routes to EReader,
        // whose first step is `PalmDb::parse(input)?`; a truncated buffer makes
        // that a terminal `Format` error, which dispatch must surface as-is.
        let keys = KeyStore::new();
        assert!(matches!(
            decrypt(&[0u8; 8], "pdb", &keys),
            Err(SchemeError::Format(_))
        ));
    }
}
