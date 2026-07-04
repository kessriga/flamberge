//! eReader content extraction: text pages, v272 footnotes/sidebars, images, and
//! the PML high-byte escaping. Text pages are `zlib(DES(fixKey(content_key),
//! record))`; footnote/sidebar id records are first de-obfuscated through the
//! header XOR table (§8.3). Reference: `docs/DEDRM_SCHEMES.md` §8
//! (`erdr2pml.py` `EreaderProcessor.getText` / `getImage` / `cleanPML`).

use std::io::Read;

use flamberge_crypto::des;
use flamberge_formats::palmdb::PalmDb;
use flamberge_formats::FormatError;

use super::header::Header;
use crate::{Result, SchemeError};

fn invalid(msg: impl Into<String>) -> SchemeError {
    SchemeError::Format(FormatError::Invalid(msg.into()))
}

/// `erdr2pml.py::deXOR`: XOR `text` against `table` starting at index `sp`,
/// wrapping around the table. An empty table is a no-op (the original would
/// divide by zero; a malformed book simply yields un-decoded ids).
pub(super) fn de_xor(text: &[u8], sp: usize, table: &[u8]) -> Vec<u8> {
    if table.is_empty() {
        return text.to_vec();
    }
    let mut out = Vec::with_capacity(text.len());
    let mut j = sp % table.len();
    for &b in text {
        out.push(table[j] ^ b);
        j += 1;
        if j == table.len() {
            j = 0;
        }
    }
    out
}

/// `erdr2pml.py::cleanPML`: escape every byte ≥ 0x80 to its PML `\aNNN` decimal
/// form (cp1252). Bytes < 0x80 pass through unchanged.
pub(super) fn clean_pml(pml: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(pml.len());
    for &b in pml {
        if b >= 0x80 {
            out.extend_from_slice(format!("\\a{b:03}").as_bytes());
        } else {
            out.push(b);
        }
    }
    out
}

/// zlib-inflate (RFC 1950, with header) a DES-decrypted text record. Trailing
/// bytes beyond the zlib stream (the cookie tail on record 1) are ignored.
fn zlib_inflate(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::ZlibDecoder::new(data)
        .read_to_end(&mut out)
        .map_err(|_| invalid("eReader text record is not valid zlib"))?;
    Ok(out)
}

/// Decrypt+inflate one page record with the content key.
fn page(content_key: &[u8], db: &PalmDb, data: &[u8], index: usize) -> Result<Vec<u8>> {
    let record = db
        .record(data, index)
        .ok_or_else(|| invalid(format!("eReader page record {index} missing")))?;
    let plain = des::ecb_decrypt(content_key, record)?;
    zlib_inflate(&plain)
}

/// Extract the full PML body: text pages, then (v272) footnote and sidebar
/// blocks. `content_key` is the raw book key; it is `fixKey`-conditioned here.
pub(super) fn extract_pml(
    header: &Header,
    db: &PalmDb,
    data: &[u8],
    content_key: &[u8],
) -> Result<Vec<u8>> {
    let key = des::fix_key(content_key);
    let mut out = Vec::new();

    // Text pages are records 1..=num_text_pages (record 1 doubles as page 0).
    for i in 0..header.num_text_pages {
        out.extend_from_slice(&page(&key, db, data, 1 + i)?);
    }

    if header.num_footnote_pages > 0 {
        out.push(b'\n');
        append_notes(
            &mut out,
            &key,
            db,
            data,
            &header.xortable,
            header.first_footnote_page,
            header.num_footnote_pages,
            "footnote",
        )?;
    }

    if header.num_sidebar_pages > 0 {
        out.push(b'\n');
        append_notes(
            &mut out,
            &key,
            db,
            data,
            &header.xortable,
            header.first_sidebar_page,
            header.num_sidebar_pages,
            "sidebar",
        )?;
    }

    Ok(out)
}

/// Emit `<tag id="…">…</tag>` blocks for a footnote or sidebar section. Record 0
/// of the section is a de-XOR'd table of `id` strings; records 1.. are the
/// encrypted+zlib'd bodies (§8.3).
#[allow(clippy::too_many_arguments)]
fn append_notes(
    out: &mut Vec<u8>,
    key: &[u8],
    db: &PalmDb,
    data: &[u8],
    xortable: &[u8],
    first_page: usize,
    num_pages: usize,
    tag: &str,
) -> Result<()> {
    let id_record = db
        .record(data, first_page)
        .ok_or_else(|| invalid(format!("eReader {tag} id record missing")))?;
    let ids = de_xor(id_record, 0, xortable);

    let mut cursor = 0usize;
    for i in 1..num_pages {
        // Each id entry: [2 bytes skipped][len byte][len bytes id][+1 trailer].
        let id_len = *ids
            .get(cursor + 2)
            .ok_or_else(|| invalid(format!("eReader {tag} id table truncated")))?
            as usize;
        let id = ids
            .get(cursor + 3..cursor + 3 + id_len)
            .ok_or_else(|| invalid(format!("eReader {tag} id table truncated")))?;
        let id = String::from_utf8_lossy(id);

        out.extend_from_slice(format!("<{tag} id=\"{id}\">\n").as_bytes());
        out.extend_from_slice(&page(key, db, data, first_page + i)?);
        out.extend_from_slice(format!("\n</{tag}>\n").as_bytes());

        cursor += id_len + 4;
    }
    Ok(())
}

/// Extract the book's images (unencrypted): a 32-byte cp1252 name at offset 4,
/// data from offset 62. Records that fall outside the file are skipped.
pub(super) fn extract_images(db: &PalmDb, data: &[u8], header: &Header) -> Vec<(String, Vec<u8>)> {
    let mut images = Vec::new();
    for i in 0..header.num_image_pages {
        let Some(record) = db.record(data, header.first_image_page + i) else {
            continue;
        };
        let Some(name_bytes) = record.get(4..36) else {
            continue;
        };
        let name = sanitize_filename(name_bytes);
        if name.is_empty() {
            continue;
        }
        let body = record.get(62..).unwrap_or_default().to_vec();
        images.push((name, body));
    }
    images
}

/// Decode a cp1252/latin-1 byte name (NUL-trimmed) and strip characters that
/// are hostile to a filename, mirroring `erdr2pml.py::sanitizeFileName` for the
/// cases that matter to a stored ZIP entry.
pub(super) fn sanitize_filename(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    bytes[..end]
        .iter()
        .filter(|&&b| b >= 0x20)
        .map(|&b| match b {
            b'<' => '[',
            b'>' => ']',
            b'/' | b'\\' | b'|' => '_',
            b':' => '-',
            b'"' => '\'',
            _ => b as char, // latin-1: byte value is the code point
        })
        .collect::<String>()
        .trim()
        .trim_matches('.')
        .to_string()
}
