//! Barnes & Noble "ignoble" offline key generation from account name + card.
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §4.2 (`ignoblekeygen.py::generate_key`).

use crate::Result;
use base64::{engine::general_purpose::STANDARD, Engine};
use flamberge_crypto::{aes, digest};

fn normalize(s: &str) -> Vec<u8> {
    s.to_lowercase()
        .chars()
        .filter(|&c| c != ' ')
        .collect::<String>()
        .into_bytes()
}

/// Generate the 28-char base64 user key ("ccHash") from name + credit-card number.
pub fn generate_key(name: &str, ccn: &str) -> Result<String> {
    let mut name = normalize(name);
    name.push(0x00);
    let mut ccn = normalize(ccn);
    ccn.push(0x00);

    let name_sha = &digest::sha1(&name)[..16]; // AES IV
    let ccn_sha = &digest::sha1(&ccn)[..16]; // AES-128 key

    let mut both = name.clone();
    both.extend_from_slice(&ccn);
    let both_sha = digest::sha1(&both); // 20 bytes

    // Plaintext = both_sha (20) ‖ 0x0c × 12 = 32 bytes; no cipher padding.
    let mut plaintext = both_sha.to_vec();
    plaintext.resize(plaintext.len() + 0x0c, 0x0c);

    let crypt = aes::cbc_encrypt(ccn_sha, name_sha, &plaintext)?;
    let userkey = digest::sha1(&crypt); // 20 bytes
    Ok(STANDARD.encode(userkey)) // 28 chars
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_28_chars() {
        let key = generate_key("John Smith", "1234 5678 9012 3456").unwrap();
        assert_eq!(key.len(), 28);
        assert!(key.ends_with('='));
    }

    #[test]
    fn normalization_is_stable() {
        // Spaces and case must not matter.
        let a = generate_key("John Smith", "1234567890123456").unwrap();
        let b = generate_key("JOHN  SMITH", "1234 5678 9012 3456").unwrap();
        assert_eq!(a, b);
    }
}
