//! Kobo (KEPUB) DRM removal.
//!
//! Flow (§9): read per-file page keys from the Kobo SQLite DB → for each
//! candidate user key: AES-128-ECB unwrap the page key, AES-128-ECB decrypt file
//! contents, strip CMS/PKCS#7 padding, validate content → repackage EPUB.
//! Candidate keys from `flamberge_keys::kobo`. Reference: `docs/DEDRM_SCHEMES.md` §9.
//! **STUB.**

use crate::{DecryptedBook, KeyStore, Result, SchemeError};

pub fn decrypt(_input: &[u8], _keys: &KeyStore) -> Result<DecryptedBook> {
    Err(SchemeError::Unimplemented("kobo::decrypt"))
}
