//! eReader / Palm (`.pdb`) DRM removal.
//!
//! Flow (§8): parse Palm PDB → record-0 version (259/260/272) → record-1 DRM
//! cookie (DES over first 8 bytes, unshuffle) → recover content key via
//! `DES(fixKey(user_key))` and SHA-1 validation → per text record
//! `zlib(DES(fixKey(content_key), record))` → PML. User key from
//! `flamberge_keys::ereader`. Reference: `docs/DEDRM_SCHEMES.md` §8.  **STUB.**

use crate::{DecryptedBook, KeyStore, Result, SchemeError};
use flamberge_formats::palmdb::PalmDb;

pub fn detect(data: &[u8]) -> bool {
    PalmDb::parse(data)
        .map(|db| &db.type_creator == b"PNRdPPrs" || &db.type_creator == b"PDctPPrs")
        .unwrap_or(false)
}

pub fn decrypt(_input: &[u8], _keys: &KeyStore) -> Result<DecryptedBook> {
    Err(SchemeError::Unimplemented("ereader::decrypt"))
}
