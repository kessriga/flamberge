//! Adobe ADEPT DRM removal (EPUB + PDF).
//!
//! EPUB (§7.3): RSA-unwrap `rights.xml` book key → AES-128-CBC per file (IV =
//! first 16 ciphertext bytes) → strip PKCS#7 → raw inflate. PDF (§7.4): unwrap
//! `ADEPT_LICENSE` (EBX_HANDLER) → RC4 per object with MD5-derived key.
//! Reference: `docs/DEDRM_SCHEMES.md` §7.  **STUB.**

use crate::{DecryptedBook, KeyStore, Result, SchemeError};

pub fn decrypt_epub(_input: &[u8], _keys: &KeyStore) -> Result<DecryptedBook> {
    Err(SchemeError::Unimplemented("adept::decrypt_epub"))
}

pub fn decrypt_pdf(_input: &[u8], _keys: &KeyStore) -> Result<DecryptedBook> {
    Err(SchemeError::Unimplemented("adept::decrypt_pdf"))
}
