//! KFX / KDF DRM removal via Amazon ION.
//!
//! Flow (§3): unzip → find DRMION + voucher members by magic → split PID into
//! (dsn, secret) → build `shared`, `obfuscate`, HMAC-SHA256 → AES-256-CBC unwrap
//! voucher → extract 16-byte content key → AES-128-CBC decrypt pages (+ LZMA).
//! Reference: `docs/DEDRM_SCHEMES.md` §3.  **STUB** (needs the ION parser).

use crate::{DecryptedBook, KeyStore, Result, SchemeError};

pub fn detect(data: &[u8]) -> bool {
    // KFX-ZIP is a plain zip; membership is confirmed by finding a DRMION member.
    data.starts_with(b"PK\x03\x04")
}

pub fn decrypt(_input: &[u8], _keys: &KeyStore) -> Result<DecryptedBook> {
    Err(SchemeError::Unimplemented("kfx::decrypt"))
}
