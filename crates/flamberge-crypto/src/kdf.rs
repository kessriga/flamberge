//! Key-derivation helpers: HMAC-SHA256, PBKDF2-HMAC-SHA1, and PKCS#7 unpadding.
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §1.5 (PBKDF2), §3.3 (KFX voucher HMAC),
//! §6 (Kindle `.kinf`).

use crate::{CryptoError, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256(key, msg) → 32 bytes. Used to derive the KFX voucher KEK.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// PBKDF2-HMAC-SHA1, output truncated to `out_len` bytes.
pub fn pbkdf2_sha1(password: &[u8], salt: &[u8], rounds: u32, out_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; out_len];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, salt, rounds, &mut out);
    out
}

/// Strip PKCS#7 padding from a decrypted block-aligned buffer.
///
/// The last byte gives the pad length; every padding byte must equal it.
/// A padding failure is the canonical wrong-key signal in several schemes.
pub fn pkcs7_unpad(data: &[u8], block: usize) -> Result<Vec<u8>> {
    let n = *data.last().ok_or(CryptoError::BadPadding)? as usize;
    if n == 0 || n > block || n > data.len() {
        return Err(CryptoError::BadPadding);
    }
    if data[data.len() - n..].iter().any(|&b| b as usize != n) {
        return Err(CryptoError::BadPadding);
    }
    Ok(data[..data.len() - n].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs7_strips() {
        let padded = b"hello\x03\x03\x03";
        assert_eq!(pkcs7_unpad(padded, 8).unwrap(), b"hello");
    }

    #[test]
    fn pkcs7_rejects_bad() {
        assert!(pkcs7_unpad(b"hello\x03\x02\x03", 8).is_err());
    }
}
