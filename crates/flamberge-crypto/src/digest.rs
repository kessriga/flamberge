//! Hash digests used across the key-derivation code (MD5, SHA-1, SHA-256).
//!
//! Thin one-shot helpers over the RustCrypto `Digest` trait.
//! Reference: `docs/DEDRM_SCHEMES.md` §1, §4.2, §6, §9.

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// MD5 → 16 bytes.
pub fn md5(data: &[u8]) -> [u8; 16] {
    Md5::digest(data).into()
}

/// SHA-1 → 20 bytes.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    Sha1::digest(data).into()
}

/// SHA-256 → 32 bytes.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Lowercase hex of a SHA-256 digest (Kobo `deviceid`/`userkey` derivation).
pub fn sha256_hex(data: &[u8]) -> String {
    let d = sha256(data);
    let mut s = String::with_capacity(64);
    for b in d {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}
