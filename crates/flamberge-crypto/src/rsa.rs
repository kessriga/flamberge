//! RSA private-key operations for Adobe ADEPT (§7).
//!
//! ADEPT wraps the 16-byte AES book key in an RSA block that the reference
//! decryptor (`ineptepub.py`) unwraps with OpenSSL's **`RSA_NO_PADDING`** — a
//! textbook `c^d mod n` that yields the full modulus-sized block — and then
//! applies its own separator rule (`block[-17] == 0x00` → book key is the last
//! 16 bytes). This module provides only the raw primitive; the ADEPT/B&N schemes
//! apply the separator rule so their behavior matches the original byte-for-byte.
//!
//! The external `rsa` crate is referenced as `::rsa` throughout so it is not
//! shadowed by this module's name.
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §7.1, §7.3.

use ::rsa::pkcs1::DecodeRsaPrivateKey;
use ::rsa::traits::{PrivateKeyParts, PublicKeyParts};
use ::rsa::{BigUint, RsaPrivateKey};

use crate::{CryptoError, Result};

/// Textbook RSA private decrypt (`c^d mod n`) with **no padding removal**,
/// matching OpenSSL `RSA_NO_PADDING`.
///
/// `der` is a PKCS#1 `RSAPrivateKey` DER (the portable ADEPT "adobekey.der");
/// `ciphertext` is the raw wrapped block (128 bytes for a 1024-bit key). The
/// result is left-padded with zeros to the modulus size so callers can index
/// from the end (the ADEPT `[-17]==0x00` rule). A ciphertext that is not a
/// valid residue mod `n` is rejected rather than silently reduced.
pub fn private_decrypt_raw(der: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let key = RsaPrivateKey::from_pkcs1_der(der)
        .map_err(|e| CryptoError::Rsa(format!("parse RSAPrivateKey DER: {e}")))?;

    let modulus_bytes = key.size();
    let c = BigUint::from_bytes_be(ciphertext);
    if &c >= key.n() {
        return Err(CryptoError::Rsa(
            "ciphertext is not less than the modulus".into(),
        ));
    }

    let m = c.modpow(key.d(), key.n());
    let raw = m.to_bytes_be();
    if raw.len() > modulus_bytes {
        // Cannot happen for m < n, but guard rather than panic on a bad key.
        return Err(CryptoError::Rsa("plaintext exceeds modulus size".into()));
    }

    let mut out = vec![0u8; modulus_bytes - raw.len()];
    out.extend_from_slice(&raw);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::rsa::pkcs1::EncodeRsaPrivateKey;

    /// Raw RSA public operation (`m^e mod n`), the inverse of
    /// [`private_decrypt_raw`], used only to synthesize a wrapped block.
    fn public_encrypt_raw(key: &RsaPrivateKey, block: &[u8]) -> Vec<u8> {
        let m = BigUint::from_bytes_be(block);
        let c = m.modpow(key.e(), key.n());
        let raw = c.to_bytes_be();
        let mut out = vec![0u8; key.size() - raw.len()];
        out.extend_from_slice(&raw);
        out
    }

    /// A PKCS#1 v1.5 encryption block: `0x00 0x02 <nonzero padding> 0x00 <payload>`.
    fn pkcs1_v15_block(modulus_bytes: usize, payload: &[u8]) -> Vec<u8> {
        let pad_len = modulus_bytes - payload.len() - 3;
        let mut block = Vec::with_capacity(modulus_bytes);
        block.push(0x00);
        block.push(0x02);
        block.extend(std::iter::repeat_n(0xFFu8, pad_len)); // nonzero padding
        block.push(0x00);
        block.extend_from_slice(payload);
        block
    }

    #[test]
    fn raw_decrypt_round_trips_a_padded_block() {
        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new(&mut rng, 1024).expect("keygen");
        let der = key.to_pkcs1_der().expect("der").as_bytes().to_vec();

        let payload = [0xABu8; 16];
        let block = pkcs1_v15_block(key.size(), &payload);
        let wrapped = public_encrypt_raw(&key, &block);

        let recovered = private_decrypt_raw(&der, &wrapped).unwrap();
        // Full block comes back, leading zero preserved.
        assert_eq!(recovered, block);
        assert_eq!(recovered.len(), key.size());
        // The ADEPT separator sits at index -17 and the key is the last 16 bytes.
        assert_eq!(recovered[recovered.len() - 17], 0x00);
        assert_eq!(&recovered[recovered.len() - 16..], &payload);
    }

    #[test]
    fn rejects_ciphertext_at_or_above_modulus() {
        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new(&mut rng, 1024).expect("keygen");
        let der = key.to_pkcs1_der().expect("der").as_bytes().to_vec();

        // n itself, as a big-endian byte string, is not a valid residue.
        let n_bytes = key.n().to_bytes_be();
        assert!(private_decrypt_raw(&der, &n_bytes).is_err());
    }

    #[test]
    fn rejects_malformed_der() {
        assert!(private_decrypt_raw(b"not a der key", &[0u8; 128]).is_err());
    }
}
