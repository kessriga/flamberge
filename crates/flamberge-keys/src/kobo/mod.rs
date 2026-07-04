//! Kobo user-key derivation and on-host discovery.
//!
//! The pure derivation ([`derive_userkeys`]) turns MAC-addresses/serials and
//! `UserID`s into candidate 16-byte AES keys. [`discover_userkeys`] gathers
//! those inputs from the current host: it locates the Kobo library SQLite DB
//! ([`host::find_kobo_db`]), reads the `UserID`s ([`db::read_userids`]),
//! enumerates NIC MAC addresses, and (for a mounted device) reads the device
//! serial from `device.xml`.
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §9.1–9.2; obok `KoboLibrary`.

mod db;
mod host;

use crate::{KeyError, Result};
use flamberge_crypto::digest;

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

/// Locate the Kobo library DB on this host, read its `UserID`s, enumerate NIC
/// MAC addresses (plus the device serial when a mounted device is found), and
/// derive the candidate user keys via [`derive_userkeys`].
///
/// Returns [`KeyError::NotFound`] — never panics — when the DB is missing, has
/// no `UserID`s, or no MAC addresses/serials are available (§9.2).
pub fn discover_userkeys() -> Result<Vec<[u8; 16]>> {
    let host::LocatedDb {
        db_bytes,
        device_root,
    } = host::find_kobo_db()?;

    let userids = db::read_userids(db_bytes)?;
    if userids.is_empty() {
        return Err(KeyError::NotFound(
            "the Kobo database has no UserID rows".into(),
        ));
    }

    let mut macaddrs = host::enumerate_macaddrs();
    if let Some(root) = &device_root {
        if let Some(serial) = host::device_serial(root) {
            macaddrs.push(serial);
        }
    }
    if macaddrs.is_empty() {
        return Err(KeyError::NotFound(
            "no MAC addresses or device serials found on this host".into(),
        ));
    }

    Ok(derive_userkeys(&macaddrs, &userids))
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

    /// AC#5: drive derive inputs off a fixture DB's UserIDs + a fixed MAC and
    /// assert a non-empty candidate set (the full discover path's crypto tail).
    #[test]
    fn derives_from_fixture_userids() {
        let file = tempfile::NamedTempFile::new().unwrap();
        {
            let conn = rusqlite::Connection::open(file.path()).unwrap();
            conn.execute("CREATE TABLE user (UserID TEXT)", []).unwrap();
            conn.execute(
                "INSERT INTO user (UserID) VALUES ('11111111-2222-3333-4444-555555555555')",
                [],
            )
            .unwrap();
        }
        let db_bytes = std::fs::read(file.path()).unwrap();
        let userids = db::read_userids(db_bytes).unwrap();
        assert!(!userids.is_empty());

        let macs = vec!["A4:83:E7:1B:2C:3D".to_string()];
        let keys = derive_userkeys(&macs, &userids);
        assert_eq!(keys.len(), KOBO_HASH_KEYS.len());
        assert!(!keys.is_empty());
    }
}
