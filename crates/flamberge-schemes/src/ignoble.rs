//! Barnes & Noble ("ignoble") DRM removal (EPUB + PDF).
//!
//! EPUB (§4.4): AES-128-CBC unwrap `rights.xml` key with `user_key[:16]`
//! (zero IV) → book key = last 16 bytes → per file AES-CBC, drop first 16 bytes,
//! strip PKCS#7, raw inflate. PDF (§4.5): EBX_HANDLER + RC4 per object.
//! B&N user keys are generated offline via `flamberge_keys::ignoble`.
//! Reference: `docs/DEDRM_SCHEMES.md` §4.  **STUB.**

use crate::{DecryptedBook, KeyStore, Result, SchemeError};

pub fn decrypt_epub(_input: &[u8], _keys: &KeyStore) -> Result<DecryptedBook> {
    Err(SchemeError::Unimplemented("ignoble::decrypt_epub"))
}

pub fn decrypt_pdf(_input: &[u8], _keys: &KeyStore) -> Result<DecryptedBook> {
    Err(SchemeError::Unimplemented("ignoble::decrypt_pdf"))
}
