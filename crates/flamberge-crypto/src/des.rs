//! Single-DES wrappers (eReader content, Kindle Android V2 obfuscation).
//!
//! DeDRM uses DES-ECB (8-byte key/block, no padding) for eReader, and DES-CBC
//! for the Android `AmazonSecureStorage.xml` V2 obfuscation.
//! Reference: `docs/DEDRM_SCHEMES.md` §1.4 / §8.

use crate::{CryptoError, Result};
use cipher::block_padding::NoPadding;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit};

/// DES-ECB decrypt, no padding. `data` must be a multiple of 8 bytes.
pub fn ecb_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    ecb::Decryptor::<des::Des>::new_from_slice(key)
        .map_err(|_| CryptoError::KeyLength {
            expected: 8,
            got: key.len(),
        })?
        .decrypt_padded_vec_mut::<NoPadding>(data)
        .map_err(|_| CryptoError::NotBlockAligned(data.len(), 8))
}

/// DES-ECB encrypt, no padding. `data` must be a multiple of 8 bytes.
///
/// The inverse of [`ecb_decrypt`]; eReader never encrypts on a real code path,
/// but the round-trip pairing keeps every cipher testable and lets callers
/// build fixtures. Reference: `docs/DEDRM_SCHEMES.md` §1.4.
pub fn ecb_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() % 8 != 0 {
        return Err(CryptoError::NotBlockAligned(data.len(), 8));
    }
    Ok(ecb::Encryptor::<des::Des>::new_from_slice(key)
        .map_err(|_| CryptoError::KeyLength {
            expected: 8,
            got: key.len(),
        })?
        .encrypt_padded_vec_mut::<NoPadding>(data))
}

/// DES-CBC decrypt, no padding.
pub fn cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    cbc::Decryptor::<des::Des>::new_from_slices(key, iv)
        .map_err(|_| CryptoError::IvLength {
            expected: 8,
            got: iv.len(),
        })?
        .decrypt_padded_vec_mut::<NoPadding>(data)
        .map_err(|_| CryptoError::NotBlockAligned(data.len(), 8))
}

/// eReader's `fixKey`: force bit 7 (MSB) of each key byte to a parity-derived
/// value. Note this operates on the **MSB**, not the standard DES LSB parity.
/// Reference: `docs/DEDRM_SCHEMES.md` §8.2.
pub fn fix_key(key: &[u8]) -> Vec<u8> {
    key.iter()
        .map(|&b| {
            let fold = b
                ^ (b << 1)
                ^ (b << 2)
                ^ (b << 3)
                ^ (b << 4)
                ^ (b << 5)
                ^ (b << 6)
                ^ (b << 7)
                ^ 0x80;
            b ^ (fold & 0x80)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecb_round_trip() {
        let key = b"8bytekey";
        let plain = b"eReader content page bytes here!"; // 32 bytes, 8-aligned
        let ct = ecb_encrypt(key, plain).unwrap();
        assert_eq!(ecb_decrypt(key, &ct).unwrap(), plain);
        assert_ne!(&ct[..], &plain[..]);
    }

    #[test]
    fn ecb_rejects_unaligned() {
        assert!(matches!(
            ecb_encrypt(b"8bytekey", b"seven!!"),
            Err(CryptoError::NotBlockAligned(7, 8))
        ));
    }
}
