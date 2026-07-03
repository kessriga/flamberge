//! Kobo user-key derivation.
//!
//! The pure derivation (`derive_userkeys`) is implemented; discovering the
//! inputs (MAC addresses, device serials, `UserID`s from the Kobo SQLite DB)
//! is host-specific and stubbed. Reference: `docs/DEDRM_SCHEMES.md` §9.2.

use crate::{KeyError, Result};
use dedrm_crypto::digest;

/// Salts distinguishing Kobo Desktop app versions.
pub const KOBO_HASH_KEYS: [&str; 4] = ["88b3a2e13", "XzUhGYdFp", "NoCanLook", "QJhwzAtXL"];

/// Derive all candidate 16-byte AES user keys from the cartesian product of
/// `KOBO_HASH_KEYS`, the MAC-addresses-plus-serials, and the user ids.
///
/// `deviceid = SHA256_hex(hash + macaddr)`, then
/// `userkey = unhex(SHA256_hex(deviceid + userid)[32:])` (second half → 16 bytes).
pub fn derive_userkeys(macaddrs_and_serials: &[String], userids: &[String]) -> Vec<[u8; 16]> {
    let mut keys = Vec::new();
    for hash in KOBO_HASH_KEYS {
        for mac in macaddrs_and_serials {
            let deviceid = digest::sha256_hex(format!("{hash}{mac}").as_bytes());
            for userid in userids {
                let full = digest::sha256_hex(format!("{deviceid}{userid}").as_bytes());
                // Second half of the 64-char hex digest = last 16 bytes.
                let half = &full[32..];
                if let Ok(bytes) = hex::decode(half) {
                    if bytes.len() == 16 {
                        let mut k = [0u8; 16];
                        k.copy_from_slice(&bytes);
                        keys.push(k);
                    }
                }
            }
        }
    }
    keys
}

/// Locate the Kobo library DB and enumerate device serials + user ids on this
/// host, then derive candidate keys.  **STUB** (platform discovery).
pub fn discover_userkeys() -> Result<Vec<[u8; 16]>> {
    Err(KeyError::Unimplemented("kobo::discover_userkeys"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_expected_count_and_size() {
        let macs = vec!["00:11:22:33:44:55".to_string(), "N1234567890".to_string()];
        let users = vec!["11111111-2222-3333-4444-555555555555".to_string()];
        let keys = derive_userkeys(&macs, &users);
        // 4 hash keys × 2 macs × 1 user = 8 candidate keys.
        assert_eq!(keys.len(), 8);
        assert_eq!(keys[0].len(), 16);
    }
}
