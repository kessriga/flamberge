//! PC1 / Pukall Cipher 1 — the Mobipocket / Kindle stream cipher.
//!
//! Self-synchronizing 16-bit-word stream cipher. The 16-byte key is loaded as
//! eight big-endian u16 words which are mutated as the cipher runs; `sum1`,
//! `sum2` and `keyXorVal` persist across every byte. The only asymmetry between
//! encrypt and decrypt is *when* `keyXorVal` is sampled (from the plaintext byte
//! in both directions), which makes the two operations mutual inverses.
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §1.2 / §2 (`mobidedrm.py::PC1`).

use crate::{CryptoError, Result};

const KEY_LEN: usize = 16;

/// Decrypt `src` with the 16-byte PC1 `key`.
pub fn decrypt(key: &[u8], src: &[u8]) -> Result<Vec<u8>> {
    pc1(key, src, true)
}

/// Encrypt `src` with the 16-byte PC1 `key`.
///
/// Used during key derivation (`temp_key = PC1(keyvec1, bigpid, encrypt)`),
/// not just for content.
pub fn encrypt(key: &[u8], src: &[u8]) -> Result<Vec<u8>> {
    pc1(key, src, false)
}

fn pc1(key: &[u8], src: &[u8], decryption: bool) -> Result<Vec<u8>> {
    if key.len() != KEY_LEN {
        return Err(CryptoError::KeyLength {
            expected: KEY_LEN,
            got: key.len(),
        });
    }

    // Eight big-endian 16-bit words; this array is the evolving cipher state.
    let mut wkey = [0u16; 8];
    for i in 0..8 {
        wkey[i] = ((key[i * 2] as u16) << 8) | key[i * 2 + 1] as u16;
    }

    let mut sum1: u16 = 0;
    let mut sum2: u16 = 0;
    let mut dst = Vec::with_capacity(src.len());

    for &byte in src {
        let mut temp1: u16 = 0;
        let mut byte_xor_val: u16 = 0;

        for j in 0..8u16 {
            temp1 ^= wkey[j as usize];
            // Compute wide, then mask to 16 bits at the same points as the reference.
            let sum2_tmp = (sum2 as u32)
                .wrapping_add(j as u32)
                .wrapping_mul(20021)
                .wrapping_add(sum1 as u32);
            // temp1/sum1 are u16, so wrapping arithmetic already masks to 16 bits.
            sum1 = temp1.wrapping_mul(346);
            sum2 = (sum2_tmp.wrapping_add(sum1 as u32) & 0xFFFF) as u16;
            temp1 = temp1.wrapping_mul(20021).wrapping_add(1);
            byte_xor_val ^= temp1 ^ sum2;
        }

        let mut cur = byte as u16;

        // The feedback value (`keyXorVal`) always derives from the *plaintext*
        // byte. On encrypt that is the input (sampled before the transform); on
        // decrypt it is the recovered output (sampled after). The single
        // feedback pass over `wkey` happens once, after the output byte exists.
        let mut key_xor_val = if decryption { 0 } else { cur.wrapping_mul(257) };

        cur = (cur ^ (byte_xor_val >> 8) ^ byte_xor_val) & 0xFF;

        if decryption {
            key_xor_val = cur.wrapping_mul(257);
        }
        for w in wkey.iter_mut() {
            *w ^= key_xor_val;
        }

        dst.push(cur as u8);
    }

    Ok(dst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = b"0123456789abcdef";
        let plain = b"The quick brown fox jumps over the lazy dog.";
        let ct = encrypt(key, plain).unwrap();
        assert_ne!(&ct[..], &plain[..]);
        let pt = decrypt(key, &ct).unwrap();
        assert_eq!(&pt[..], &plain[..]);
    }

    #[test]
    fn rejects_wrong_key_length() {
        assert!(matches!(
            decrypt(b"short", b"data"),
            Err(CryptoError::KeyLength { expected: 16, .. })
        ));
    }
}
