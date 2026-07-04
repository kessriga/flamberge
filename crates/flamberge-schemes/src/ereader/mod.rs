//! eReader / Palm (`.pdb`) DRM removal.
//!
//! Flow (§8): parse the Palm PDB → record-0 version gate (259/260/272) →
//! record-1 DRM cookie (DES over its own first 8 bytes, then unshuffle) → recover
//! the content key by DES-unwrapping the header's `encrypted_key` with
//! `fixKey(user_key)` and validating `SHA1(content_key)` → per-record
//! `zlib(DES(fixKey(content_key), record))` → PML, packaged as a stored `.pmlz`
//! alongside extracted images. User keys come from `flamberge_keys::ereader`.
//! Reference: `docs/DEDRM_SCHEMES.md` §8 (`erdr2pml.py`).

mod content;
mod header;

use flamberge_crypto::{des, digest};
use flamberge_formats::palmdb::PalmDb;
use flamberge_formats::{pmlz, FormatError};

use crate::{DecryptedBook, KeyStore, Result, SchemeError};

const BOOK_MAGIC: &[u8; 8] = b"PNRdPPrs";
const DICT_MAGIC: &[u8; 8] = b"PDctPPrs";

/// True if `data` is an eReader Palm database (book or dictionary).
pub fn detect(data: &[u8]) -> bool {
    PalmDb::parse(data)
        .map(|db| &db.type_creator == BOOK_MAGIC || &db.type_creator == DICT_MAGIC)
        .unwrap_or(false)
}

fn invalid(msg: impl Into<String>) -> SchemeError {
    SchemeError::Format(FormatError::Invalid(msg.into()))
}

/// Decrypt a DRM'd eReader `.pdb` into a `.pmlz`, trying each candidate eReader
/// user key until one validates against the book's stored SHA-1 digest.
pub fn decrypt(input: &[u8], keys: &KeyStore) -> Result<DecryptedBook> {
    let db = PalmDb::parse(input)?;
    let is_book = &db.type_creator == BOOK_MAGIC;
    if !is_book && &db.type_creator != DICT_MAGIC {
        return Err(SchemeError::NotThisScheme);
    }

    let record0 = db
        .record(input, 0)
        .ok_or_else(|| invalid("eReader file has no record 0"))?;
    let record1 = db
        .record(input, 1)
        .ok_or_else(|| invalid("eReader file has no record 1"))?;
    let header = header::parse(record0, record1, is_book)?;

    // The header is key-independent; only the content-key unwrap depends on the
    // user key. Accept the first candidate whose SHA-1 matches the book.
    let content_key = keys
        .ereader_keys
        .iter()
        .find_map(|user_key| {
            let key = des::ecb_decrypt(&des::fix_key(user_key), &header.encrypted_key).ok()?;
            (digest::sha1(&key) == header.encrypted_key_sha).then_some(key)
        })
        .ok_or(SchemeError::NoKeyWorked)?;

    let pml = content::clean_pml(&content::extract_pml(&header, &db, input, &content_key)?);
    let images = content::extract_images(&db, input, &header);

    let bookname = {
        let name = content::sanitize_filename(&db.name);
        if name.is_empty() {
            "book".to_string()
        } else {
            name
        }
    };
    let data = pmlz::write(&format!("{bookname}.pml"), &pml, &images)?;

    Ok(DecryptedBook {
        data,
        extension: "pmlz".to_string(),
        title: Some(bookname),
    })
}

#[cfg(test)]
mod tests;
