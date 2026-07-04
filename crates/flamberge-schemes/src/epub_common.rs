//! Shared OCF/EPUB decryption helpers used by both the Adobe ADEPT (§7.3) and
//! Barnes & Noble (§4.4) schemes. The two differ only in how the book key is
//! unwrapped; the per-file member decryption and base64 handling are identical.
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §4.4 / §7.3.

use std::io::Read;

use base64::Engine;
use flamberge_crypto::{aes, kdf};

use crate::{Result, SchemeError};

/// Decrypt one encrypted OCF member with a recovered 16-byte book key.
///
/// AES-128-CBC with IV = the first 16 ciphertext bytes over the remainder. This
/// is exactly the reference schemes' "decrypt the whole blob with a zero IV,
/// then drop the first 16 plaintext bytes": CBC block `i` is `D(Cᵢ) ⊕ Cᵢ₋₁`, so
/// keying the first stored block in as the IV yields the same blocks 1..n while
/// discarding block 0. Then strip PKCS#7 and raw inflate. A member that was
/// stored (not deflated) fails inflate and passes through unchanged (§4.4/§7.3).
pub(crate) fn decrypt_member(book_key: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 16 || data.len() % 16 != 0 {
        return Err(invalid(
            "EPUB encrypted member is not a whole number of AES blocks",
        ));
    }
    let (iv, ciphertext) = data.split_at(16);
    let plain = aes::cbc_decrypt(book_key, iv, ciphertext)?;
    let plain = kdf::pkcs7_unpad(&plain, 16)?;
    Ok(raw_inflate(&plain).unwrap_or(plain))
}

/// Raw DEFLATE inflate (RFC 1951, zlib `windowBits = -15`). Returns `None` on any
/// error so the caller passes the bytes through unchanged, matching the reference
/// `decompress`'s bare `except: return bytes`.
fn raw_inflate(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::DeflateDecoder::new(data)
        .read_to_end(&mut out)
        .ok()
        .map(|_| out)
}

/// Decode base64, tolerating embedded whitespace as the reference codec does.
pub(crate) fn decode_b64(s: &str) -> Result<Vec<u8>> {
    let compact: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(compact.as_bytes())
        .map_err(|e| invalid(&format!("invalid base64 wrapped key: {e}")))
}

/// Wrap a message in a `FormatError::Invalid` scheme error.
pub(crate) fn invalid(msg: &str) -> SchemeError {
    SchemeError::Format(flamberge_formats::FormatError::Invalid(msg.to_string()))
}
