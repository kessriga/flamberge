//! Windows ADEPT key algorithm: DPAPI entropy layout + AES-wrapped key decrypt.
//!
//! On Windows the RSA private key is stored AES-128-CBC-wrapped under a `keykey`
//! that DPAPI (`CryptUnprotectData`) releases only against a 32-byte, machine-
//! bound entropy. This module implements the two portable, testable pieces of
//! that flow — the entropy byte layout ([`pack_entropy`]) and the wrapped-key
//! decrypt ([`decrypt_private_license_key`]).
//!
//! The remaining steps are **not reproducible offline** and are therefore *not*
//! implemented here (see `adobe::extract_keys`, which returns `Unsupported` on
//! Windows). For a future host-bound caller, the full recipe from `adobekey.py`
//! (§7.2) is:
//!
//! 1. `serial` = `GetVolumeInformationW` serial of the system-drive root (u32).
//! 2. `vendor` = CPUID leaf 0 → `EBX‖EDX‖ECX` (12 bytes).
//! 3. `signature` = CPUID leaf 1 EAX, big-endian, low 3 bytes.
//! 4. `user` = `GetUserNameW` as UTF-16-LE, every even byte (i.e. the low byte
//!    of each code unit).
//! 5. `entropy = pack_entropy(serial, vendor, signature, user)`.
//! 6. `keykey = CryptUnprotectData(HKCU\Software\Adobe\Adept\Device["key"], entropy)`.
//! 7. For each `HKCU\Software\Adobe\Adept\Activation\NNNN` group of type
//!    `credentials`, take the `privateLicenseKey`'s `value` and run it through
//!    [`decrypt_private_license_key`].
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §7.2 (`adobekey.py`, `iswindows` branch).

use flamberge_crypto::{aes, kdf};

use super::{decode_b64, HEADER_STRIP_LEN};
use crate::{KeyError, Result};

/// Pack the 32-byte DPAPI entropy, matching `struct.pack('>I12s3s13s', ...)`.
///
/// Layout: `serial` big-endian u32 (4) ‖ `vendor` (12) ‖ `signature` (3) ‖
/// `username` in a 13-byte field, null-padded if short and truncated if long —
/// exactly Python's `s`-field semantics.
pub fn pack_entropy(
    serial: u32,
    vendor: [u8; 12],
    signature: [u8; 3],
    username: &[u8],
) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..4].copy_from_slice(&serial.to_be_bytes());
    out[4..16].copy_from_slice(&vendor);
    out[16..19].copy_from_slice(&signature);
    let user_len = username.len().min(13);
    out[19..19 + user_len].copy_from_slice(&username[..user_len]);
    out
}

/// Decrypt a Windows-stored `privateLicenseKey` into a PKCS#1 `RSAPrivateKey` DER.
///
/// `keykey` is the 16-byte AES key recovered from DPAPI; `b64` is the registry
/// `value`. AES-128-CBC decrypt with a **zero IV**, strip PKCS#7 padding, then
/// drop the fixed 26-byte header — mirroring `userkey[26:-pad]` in `adobekey.py`.
pub fn decrypt_private_license_key(keykey: &[u8], b64: &str) -> Result<Vec<u8>> {
    if keykey.len() != 16 {
        return Err(KeyError::Invalid(format!(
            "ADEPT keykey must be 16 bytes, got {}",
            keykey.len()
        )));
    }
    let wrapped = decode_b64(b64)?;
    let decrypted = aes::cbc_decrypt(keykey, &[0u8; 16], &wrapped)?;
    let unpadded = kdf::pkcs7_unpad(&decrypted, 16)?;
    if unpadded.len() <= HEADER_STRIP_LEN {
        return Err(KeyError::Invalid(format!(
            "decrypted privateLicenseKey too short: {} bytes",
            unpadded.len()
        )));
    }
    Ok(unpadded[HEADER_STRIP_LEN..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn pack_entropy_matches_struct_pack_layout() {
        // struct.pack('>I12s3s13s', 0x01020304, b'GenuineIntel', b'\x00\x06\xf2', b'alice')
        let entropy = pack_entropy(0x0102_0304, *b"GenuineIntel", [0x00, 0x06, 0xf2], b"alice");
        let mut expected = Vec::new();
        expected.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        expected.extend_from_slice(b"GenuineIntel");
        expected.extend_from_slice(&[0x00, 0x06, 0xf2]);
        expected.extend_from_slice(b"alice");
        expected.extend_from_slice(&[0u8; 8]); // 13-byte field, "alice" is 5
        assert_eq!(&entropy[..], &expected[..]);
        assert_eq!(entropy.len(), 32);
    }

    #[test]
    fn pack_entropy_truncates_long_username() {
        let entropy = pack_entropy(0, [0; 12], [0; 3], b"an-overly-long-username");
        // Only the first 13 username bytes survive.
        assert_eq!(&entropy[19..32], b"an-overly-lon");
    }

    #[test]
    fn decrypt_round_trips_a_wrapped_key() {
        let keykey = [0x11u8; 16];
        let der = [0xABu8; 40]; // stand-in DER body

        // Reproduce the on-disk blob: 26-byte header ‖ der, PKCS#7-padded to a
        // block boundary, AES-128-CBC-encrypted under a zero IV, base64'd.
        let mut plain = vec![0x5Au8; HEADER_STRIP_LEN];
        plain.extend_from_slice(&der);
        let pad = 16 - (plain.len() % 16);
        plain.extend(std::iter::repeat_n(pad as u8, pad));
        let ct = aes::cbc_encrypt(&keykey, &[0u8; 16], &plain).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&ct);

        assert_eq!(decrypt_private_license_key(&keykey, &b64).unwrap(), der);
    }

    #[test]
    fn decrypt_rejects_wrong_key_length() {
        assert!(decrypt_private_license_key(&[0u8; 8], "AAAA").is_err());
    }
}
