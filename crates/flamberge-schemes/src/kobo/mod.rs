//! Kobo (KEPUB) DRM removal.
//!
//! Flow (§9, `obok.py`): read the per-file wrapped page keys for this book from
//! the Kobo library SQLite DB → for each candidate user key, AES-128-ECB unwrap
//! each page key, AES-128-ECB decrypt the member, strip CMS/PKCS#7 padding, and
//! validate the plaintext (`check`); accept the key under which no checkable
//! member fails → repackage the archive as a plain EPUB. Candidate user keys
//! come from `flamberge_keys::kobo::derive_userkeys` (supplied via
//! `KeyStore::kobo_keys`); the DB and volume id via `KeyStore::kobo_db` /
//! `kobo_volumeid`. Reference: `docs/DEDRM_SCHEMES.md` §9.

mod content;
mod db;

use std::collections::BTreeMap;

use flamberge_formats::ocf;

use crate::{DecryptedBook, KeyStore, Result, SchemeError};
use content::{check, decrypt_member, CheckResult};

/// Local ZIP local-file-header magic; a KEPUB is a ZIP/EPUB archive.
const ZIP_MAGIC: &[u8; 4] = b"PK\x03\x04";

/// Decrypt a DRM'd Kobo KEPUB into a plain EPUB, trying each candidate Kobo user
/// key until one decrypts every member with valid content (§9.3).
pub fn decrypt(input: &[u8], keys: &KeyStore) -> Result<DecryptedBook> {
    if !input.starts_with(ZIP_MAGIC) {
        return Err(SchemeError::NotThisScheme);
    }
    let db_bytes = keys.kobo_db.as_deref().ok_or_else(|| {
        invalid(
            "Kobo decryption needs the library SQLite DB (KoboReader.sqlite); none was provided",
        )
    })?;

    let db::VolumeKeys {
        keys: wrapped_keys,
        title,
    } = db::read_volume(db_bytes, keys.kobo_volumeid.as_deref())?;

    // Path → wrapped page key for the encrypted members. Members absent from
    // this map are DRM-free and copied through by `repackage`.
    let wrapped: BTreeMap<&str, &[u8]> = wrapped_keys
        .iter()
        .map(|k| (k.elementid.as_str(), k.wrapped.as_slice()))
        .collect();

    let members = ocf::read_all_members(input)?;

    for user_key in &keys.kobo_keys {
        if let Some(replacements) = try_key(user_key, &wrapped, &members) {
            let data = ocf::repackage(input, &replacements)?;
            return Ok(DecryptedBook {
                data,
                extension: "epub".to_string(),
                title,
            });
        }
    }
    Err(SchemeError::NoKeyWorked)
}

/// Attempt to decrypt every encrypted member with one candidate user key.
/// Returns the decrypted replacements when no checkable member fails validation,
/// or `None` (this key is wrong) on the first content-check failure or cipher
/// error.
fn try_key(
    user_key: &[u8; 16],
    wrapped: &BTreeMap<&str, &[u8]>,
    members: &[(String, Vec<u8>)],
) -> Option<BTreeMap<String, Vec<u8>>> {
    let mut replacements = BTreeMap::new();
    for (name, ciphertext) in members {
        let Some(&page_key) = wrapped.get(name.as_str()) else {
            continue; // DRM-free member; leave for `repackage` to copy.
        };
        let plain = decrypt_member(user_key, page_key, ciphertext).ok()?;
        if check(name, &plain) == CheckResult::Failed {
            return None;
        }
        replacements.insert(name.clone(), plain);
    }
    Some(replacements)
}

fn invalid(msg: impl Into<String>) -> SchemeError {
    SchemeError::Format(flamberge_formats::FormatError::Invalid(msg.into()))
}

#[cfg(test)]
mod tests;
