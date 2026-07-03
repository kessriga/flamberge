//! EPUB / OCF (Open Container Format) helpers for ADEPT and B&N EPUBs.
//!
//! Reads `META-INF/rights.xml` (wrapped book key) and `META-INF/encryption.xml`
//! (which files are encrypted), and repackages a decrypted zip with `mimetype`
//! stored first. Reference: `docs/DEDRM_SCHEMES.md` §4.4 / §7.3.  **STUB.**

use crate::{FormatError, Result};

pub const RIGHTS_XML: &str = "META-INF/rights.xml";
pub const ENCRYPTION_XML: &str = "META-INF/encryption.xml";
pub const MIMETYPE: &str = "mimetype";

pub const NS_ADEPT: &str = "http://ns.adobe.com/adept";
pub const NS_ENC: &str = "http://www.w3.org/2001/04/xmlenc#";

#[derive(Debug, Default)]
pub struct OcfEncryption {
    /// Base64 text of the wrapped book key from `rights.xml` (`adept:encryptedKey`).
    pub wrapped_key_b64: Option<String>,
    /// Set of zip paths listed as encrypted in `encryption.xml`.
    pub encrypted_paths: std::collections::HashSet<String>,
}

impl OcfEncryption {
    /// Parse `rights.xml` + `encryption.xml` from an EPUB zip image.  **STUB.**
    pub fn parse(_zip_data: &[u8]) -> Result<Self> {
        Err(FormatError::Unimplemented("ocf::OcfEncryption::parse"))
    }
}

/// True if the EPUB contains both ADEPT/B&N META-INF markers.  **STUB.**
pub fn is_encrypted_epub(_zip_data: &[u8]) -> Result<bool> {
    Err(FormatError::Unimplemented("ocf::is_encrypted_epub"))
}
