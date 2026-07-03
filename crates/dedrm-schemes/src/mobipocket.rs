//! Mobipocket (MOBI/AZW/PRC) DRM removal.
//!
//! Flow (§2): parse PalmDB → read record-0 crypto type → for each candidate PID
//! derive `temp_key = PC1(keyvec1, pid.pad16, encrypt)`, match voucher checksum,
//! `PC1(temp_key, cookie)` → `finalkey` → PC1-decrypt text records 1..=records
//! (stripping trailing-data bytes). Reference: `docs/DEDRM_SCHEMES.md` §2.
//!
//! **STUB** — PalmDB parsing (`dedrm_formats::palmdb`) and PC1
//! (`dedrm_crypto::pc1`) are implemented; the record/voucher logic is not.

use crate::{DecryptedBook, KeyStore, Result, SchemeError};
use dedrm_formats::palmdb::PalmDb;

/// PC1 master key for type-2 PID key derivation and the default fallback.
pub const KEYVEC1: [u8; 16] = [
    0x72, 0x38, 0x33, 0xB0, 0xB4, 0xF2, 0xE3, 0xCA, 0xDF, 0x09, 0x01, 0xD6, 0xE2, 0xE0, 0x3F, 0x96,
];
/// Type-1 (old Mobipocket) fixed book-key vector.
pub const T1_KEYVEC: &[u8; 16] = b"QDCVEPMU675RUBSZ";

/// True if this looks like a Mobipocket PalmDB (`BOOKMOBI` / `TEXtREAd`).
pub fn detect(data: &[u8]) -> bool {
    PalmDb::parse(data)
        .map(|db| &db.type_creator == b"BOOKMOBI" || &db.type_creator == b"TEXtREAd")
        .unwrap_or(false)
}

pub fn decrypt(_input: &[u8], _keys: &KeyStore) -> Result<DecryptedBook> {
    Err(SchemeError::Unimplemented("mobipocket::decrypt"))
}
