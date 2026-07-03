//! Topaz (TPZ) DRM removal.
//!
//! Flow (§5): parse `TPZ0` container → read `dkey` → for each candidate PID
//! (8 bytes) Topaz-decrypt each dkey sub-record, validate the `PID..pid` magic
//! and embedded PID → recover 8-byte book key → Topaz-decrypt + zlib-inflate the
//! encrypted payload records. Reference: `docs/DEDRM_SCHEMES.md` §5.  **STUB.**

use crate::{DecryptedBook, KeyStore, Result, SchemeError};

pub fn detect(data: &[u8]) -> bool {
    data.starts_with(b"TPZ0") || data.starts_with(b"TPZ")
}

pub fn decrypt(_input: &[u8], _keys: &KeyStore) -> Result<DecryptedBook> {
    Err(SchemeError::Unimplemented("topaz::decrypt"))
}
