//! Kindle device/account key extraction (`.kinf`/`.k4i`, Android, eInk serials).
//!
//! The `.kinf` obfuscation layers (symbol maps, prime rotation, PBKDF2, DPAPI /
//! GCM-as-CTR) are documented in `docs/DEDRM_SCHEMES.md` §6. Platform extraction
//! is **stubbed**; note that Windows `.kinf2011` (v5) requires real DPAPI with
//! the user's profile and cannot be reproduced offline.

use crate::{KeyError, Result};

/// A decoded Kindle key database (the `.k4i` JSON contents: name → hex value).
pub type KindleDb = std::collections::HashMap<String, String>;

/// Extract Kindle keys from the locally installed Kindle for PC/Mac.  **STUB.**
pub fn extract_local_keys() -> Result<Vec<KindleDb>> {
    Err(KeyError::Unimplemented("kindle::extract_local_keys"))
}

/// Extract candidate serials from an Android `backup.ab` /
/// `AmazonSecureStorage.xml` / `map_data_storage.db`.  **STUB.**
pub fn serials_from_android(_path: &std::path::Path) -> Result<Vec<String>> {
    Err(KeyError::Unimplemented("kindle::serials_from_android"))
}

/// Parse a `.k4i` key database file (JSON).  **STUB.**
pub fn load_k4i(_path: &std::path::Path) -> Result<KindleDb> {
    Err(KeyError::Unimplemented("kindle::load_k4i"))
}
