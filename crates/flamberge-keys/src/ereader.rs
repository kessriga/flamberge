//! eReader offline user-key derivation from name + credit-card number.
//!
//! `user_key = pack('>LL', crc32(filtered_name), crc32(cc[-8:]))` — two
//! independent standard CRC-32s, big-endian, giving an 8-byte DES key.
//! Reference: `docs/DEDRM_SCHEMES.md` §8.2 (`erdr2pml.py::getuser_key`).

use flamberge_crypto::crc32;

/// Derive the 8-byte eReader user key from buyer name and credit-card number.
pub fn user_key(name: &str, cc: &str) -> [u8; 8] {
    let newname: String = name
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        .collect();
    let cc: String = cc.chars().filter(|&c| c != ' ').collect();
    let cc8: String = cc
        .chars()
        .rev()
        .take(8)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();

    let name_crc = crc32::ieee(newname.as_bytes());
    let cc_crc = crc32::ieee(cc8.as_bytes());

    let mut key = [0u8; 8];
    key[..4].copy_from_slice(&name_crc.to_be_bytes());
    key[4..].copy_from_slice(&cc_crc.to_be_bytes());
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_eight_bytes_and_space_insensitive() {
        let a = user_key("Jane Doe", "4111 1111 1111 1111");
        let b = user_key("JANE DOE", "4111111111111111");
        assert_eq!(a, b);
        assert_eq!(a.len(), 8);
    }
}
