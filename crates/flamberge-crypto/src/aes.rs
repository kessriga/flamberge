//! AES wrappers (CBC / ECB / CTR), all **no-padding**.
//!
//! DeDRM never lets the cipher add or strip PKCS#7 — callers handle padding
//! themselves (see [`crate::kdf`] helpers and the scheme crates). Key length
//! selects AES-128/192/256. Reference: `docs/DEDRM_SCHEMES.md` §1.1.

use crate::{CryptoError, Result};
use cipher::block_padding::NoPadding;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit, StreamCipher};

macro_rules! cbc_decrypt_arm {
    ($alg:ty, $key:expr, $iv:expr, $data:expr) => {
        cbc::Decryptor::<$alg>::new_from_slices($key, $iv)
            .map_err(|_| CryptoError::IvLength { expected: 16, got: $iv.len() })?
            .decrypt_padded_vec_mut::<NoPadding>($data)
            .map_err(|_| CryptoError::NotBlockAligned($data.len(), 16))
    };
}

macro_rules! cbc_encrypt_arm {
    ($alg:ty, $key:expr, $iv:expr, $data:expr) => {
        Ok(cbc::Encryptor::<$alg>::new_from_slices($key, $iv)
            .map_err(|_| CryptoError::IvLength { expected: 16, got: $iv.len() })?
            .encrypt_padded_vec_mut::<NoPadding>($data))
    };
}

macro_rules! ecb_decrypt_arm {
    ($alg:ty, $key:expr, $data:expr) => {
        ecb::Decryptor::<$alg>::new_from_slice($key)
            .map_err(|_| CryptoError::KeyLength { expected: 16, got: $key.len() })?
            .decrypt_padded_vec_mut::<NoPadding>($data)
            .map_err(|_| CryptoError::NotBlockAligned($data.len(), 16))
    };
}

macro_rules! ctr_arm {
    ($alg:ty, $key:expr, $iv:expr, $data:expr) => {{
        let mut cipher = ctr::Ctr128BE::<$alg>::new_from_slices($key, $iv)
            .map_err(|_| CryptoError::IvLength { expected: 16, got: $iv.len() })?;
        let mut buf = $data.to_vec();
        cipher.apply_keystream(&mut buf);
        Ok(buf)
    }};
}

/// AES-CBC decrypt, no padding. `data` must be block-aligned.
pub fn cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    match key.len() {
        16 => cbc_decrypt_arm!(aes::Aes128, key, iv, data),
        24 => cbc_decrypt_arm!(aes::Aes192, key, iv, data),
        32 => cbc_decrypt_arm!(aes::Aes256, key, iv, data),
        n => Err(CryptoError::KeyLength { expected: 16, got: n }),
    }
}

/// AES-CBC encrypt, no padding. `data` must be block-aligned.
pub fn cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    match key.len() {
        16 => cbc_encrypt_arm!(aes::Aes128, key, iv, data),
        24 => cbc_encrypt_arm!(aes::Aes192, key, iv, data),
        32 => cbc_encrypt_arm!(aes::Aes256, key, iv, data),
        n => Err(CryptoError::KeyLength { expected: 16, got: n }),
    }
}

/// AES-ECB decrypt, no padding, block by block.
pub fn ecb_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    match key.len() {
        16 => ecb_decrypt_arm!(aes::Aes128, key, data),
        24 => ecb_decrypt_arm!(aes::Aes192, key, data),
        32 => ecb_decrypt_arm!(aes::Aes256, key, data),
        n => Err(CryptoError::KeyLength { expected: 16, got: n }),
    }
}

/// AES-CTR keystream application (big-endian 128-bit counter). Self-inverse.
///
/// `iv` is the full 16-byte initial counter block. Used by the Kindle
/// `.kinf2018` "GCM-as-CTR" path (nonce ‖ `00 00 00 02`).
pub fn ctr_apply(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    match key.len() {
        16 => ctr_arm!(aes::Aes128, key, iv, data),
        24 => ctr_arm!(aes::Aes192, key, iv, data),
        32 => ctr_arm!(aes::Aes256, key, iv, data),
        n => Err(CryptoError::KeyLength { expected: 16, got: n }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbc_round_trip_128() {
        let key = [0x2bu8; 16];
        let iv = [0u8; 16];
        let pt = [0x11u8; 32];
        let ct = cbc_encrypt(&key, &iv, &pt).unwrap();
        assert_eq!(cbc_decrypt(&key, &iv, &ct).unwrap(), pt);
    }

    #[test]
    fn ctr_self_inverse_256() {
        let key = [7u8; 32];
        let iv = [0u8; 16];
        let data = b"kindle kinf2018 value payload!!!";
        let enc = ctr_apply(&key, &iv, data).unwrap();
        assert_eq!(ctr_apply(&key, &iv, &enc).unwrap(), data);
    }
}
