//! Barnes & Noble ("ignoble") DRM removal (EPUB + PDF).
//!
//! EPUB (§4.4): AES-128-CBC unwrap `rights.xml` key with `user_key[:16]`
//! (zero IV) → book key = last 16 bytes → per file AES-CBC, drop first 16 bytes,
//! strip PKCS#7, raw inflate. PDF (§4.5): EBX_HANDLER + RC4 per object.
//! B&N user keys are generated offline via `flamberge_keys::ignoble`.
//! Reference: `docs/DEDRM_SCHEMES.md` §4.  **Decrypt bodies are STUBBED**
//! (TASK-10); scheme *detection* is wired so ADEPT dispatch can fall through.

use flamberge_formats::ocf::{self, EpubScheme, OcfEncryption};

use crate::{DecryptedBook, KeyStore, Result, SchemeError};

/// Barnes & Noble EPUB decryption. Detection is live so `.epub` dispatch works
/// (a non-B&N container returns [`SchemeError::NotThisScheme`] and falls through
/// to ADEPT); the B&N crypto itself is pending TASK-10.
pub fn decrypt_epub(input: &[u8], _keys: &KeyStore) -> Result<DecryptedBook> {
    // Claim only B&N-shaped OCF containers (64-char wrapped key, §4.4); anything
    // else (ADEPT's 172-char key, or DRM-free) falls through.
    if !input.starts_with(b"PK\x03\x04") || !ocf::is_encrypted_epub(input)? {
        return Err(SchemeError::NotThisScheme);
    }
    if OcfEncryption::parse(input)?.scheme() != Some(EpubScheme::BarnesNoble) {
        return Err(SchemeError::NotThisScheme);
    }
    Err(SchemeError::Unimplemented("ignoble::decrypt_epub"))
}

pub fn decrypt_pdf(_input: &[u8], _keys: &KeyStore) -> Result<DecryptedBook> {
    Err(SchemeError::Unimplemented("ignoble::decrypt_pdf"))
}
