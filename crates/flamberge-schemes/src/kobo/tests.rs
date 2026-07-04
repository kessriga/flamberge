//! End-to-end Kobo decryption over a synthesized KEPUB + minimal SQLite DB.

use std::io::{Cursor, Read, Write};

use base64::Engine;
use flamberge_crypto::aes;
use flamberge_keys::{kobo::derive_userkeys, KeyStore};
use rusqlite::{params, Connection};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use super::*;

const VOLUME_ID: &str = "vol-1";
const XHTML_PATH: &str = "OEBPS/text.xhtml";
const XHTML_PLAIN: &[u8] = b"<?xml version=\"1.0\"?><html><body>hi</body></html>";
const PLAIN_PATH: &str = "OEBPS/notes.txt";
const PLAIN_CONTENT: &[u8] = b"this file is not encrypted";

fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
    let pad = 16 - (data.len() % 16);
    let mut out = data.to_vec();
    out.extend(std::iter::repeat_n(pad as u8, pad));
    out
}

/// Candidate user keys and the one chosen to encrypt the fixture (its first).
fn candidate_keys() -> Vec<[u8; 16]> {
    let macs = vec!["00:11:22:33:44:55".to_string(), "N9999999999".to_string()];
    let users = vec!["11111111-2222-3333-4444-555555555555".to_string()];
    derive_userkeys(&macs, &users)
}

/// Build a KEPUB whose `OEBPS/text.xhtml` member is two-layer-encrypted under
/// `page_key`, wrapped by `user_key`. Returns `(kepub_bytes, sqlite_bytes)`.
fn fixture(user_key: &[u8; 16]) -> (Vec<u8>, Vec<u8>) {
    let page_key = [0x5au8; 16];
    let wrapped = aes::ecb_encrypt(user_key, &page_key).unwrap();
    let elementkey_b64 = base64::engine::general_purpose::STANDARD.encode(&wrapped);
    let ciphertext = aes::ecb_encrypt(&page_key, &pkcs7_pad(XHTML_PLAIN)).unwrap();

    // KEPUB archive: mimetype (stored first), the encrypted xhtml, a plain file.
    let mut kepub = Vec::new();
    {
        let mut zw = ZipWriter::new(Cursor::new(&mut kepub));
        let stored = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        zw.start_file("mimetype", stored).unwrap();
        zw.write_all(b"application/epub+zip").unwrap();
        zw.start_file(XHTML_PATH, stored).unwrap();
        zw.write_all(&ciphertext).unwrap();
        zw.start_file(PLAIN_PATH, SimpleFileOptions::default())
            .unwrap();
        zw.write_all(PLAIN_CONTENT).unwrap();
        zw.finish().unwrap();
    }

    // Minimal Kobo library DB: content_keys(volumeid, elementid, elementkey) and
    // content(contentid, Title).
    let dbfile = tempfile::NamedTempFile::new().unwrap();
    {
        let conn = Connection::open(dbfile.path()).unwrap();
        conn.execute_batch(
            "CREATE TABLE content_keys (volumeid TEXT, elementid TEXT, elementkey TEXT);
             CREATE TABLE content (contentid TEXT, Title TEXT);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO content_keys VALUES (?1, ?2, ?3)",
            params![VOLUME_ID, XHTML_PATH, elementkey_b64],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO content VALUES (?1, ?2)",
            params![VOLUME_ID, "Test Book"],
        )
        .unwrap();
    }
    let sqlite = std::fs::read(dbfile.path()).unwrap();
    (kepub, sqlite)
}

fn member(zip: &[u8], name: &str) -> Vec<u8> {
    let mut archive = ZipArchive::new(Cursor::new(zip)).unwrap();
    let mut file = archive.by_name(name).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    bytes
}

#[test]
fn decrypts_synthesized_kepub() {
    let candidates = candidate_keys();
    let (kepub, sqlite) = fixture(&candidates[0]);

    let mut keys = KeyStore::new();
    keys.kobo_keys = candidates;
    keys.kobo_db = Some(sqlite);
    // volume id left as None → inferred from the single-volume DB.

    let book = decrypt(&kepub, &keys).unwrap();
    assert_eq!(book.extension, "epub");
    assert_eq!(book.title.as_deref(), Some("Test Book"));

    // The encrypted member is decrypted; the DRM-free member is preserved.
    assert_eq!(member(&book.data, XHTML_PATH), XHTML_PLAIN);
    assert_eq!(member(&book.data, PLAIN_PATH), PLAIN_CONTENT);
    // The output opens as a ZIP with mimetype first and stored.
    let mut out = ZipArchive::new(Cursor::new(&book.data)).unwrap();
    let mimetype = out.by_index(0).unwrap();
    assert_eq!(mimetype.name(), "mimetype");
    assert_eq!(mimetype.compression(), CompressionMethod::Stored);
}

#[test]
fn honors_explicit_volume_id() {
    let candidates = candidate_keys();
    let (kepub, sqlite) = fixture(&candidates[0]);

    let mut keys = KeyStore::new();
    keys.kobo_keys = candidates;
    keys.kobo_db = Some(sqlite);
    keys.kobo_volumeid = Some(VOLUME_ID.to_string());

    let book = decrypt(&kepub, &keys).unwrap();
    assert_eq!(member(&book.data, XHTML_PATH), XHTML_PLAIN);
}

#[test]
fn no_candidate_key_fails_clearly() {
    let candidates = candidate_keys();
    let (kepub, sqlite) = fixture(&candidates[0]);

    let mut keys = KeyStore::new();
    keys.kobo_keys = Vec::new(); // no user keys → nothing can decrypt.
    keys.kobo_db = Some(sqlite);

    assert!(matches!(
        decrypt(&kepub, &keys),
        Err(SchemeError::NoKeyWorked)
    ));
}

#[test]
fn missing_db_is_a_clear_error() {
    let (kepub, _sqlite) = fixture(&candidate_keys()[0]);
    let keys = KeyStore::new(); // no kobo_db provided.

    let err = decrypt(&kepub, &keys).unwrap_err();
    assert!(err.to_string().contains("SQLite DB"), "got: {err}");
}

#[test]
fn non_zip_input_falls_through() {
    let keys = KeyStore::new();
    assert!(matches!(
        decrypt(b"not a zip", &keys),
        Err(SchemeError::NotThisScheme)
    ));
}

#[test]
fn routes_kepub_epub_and_extensionless_via_db_signal() {
    let candidates = candidate_keys();
    let (kepub, sqlite) = fixture(&candidates[0]);

    let mut keys = KeyStore::new();
    keys.kobo_keys = candidates;
    keys.kobo_db = Some(sqlite);

    // A real Kobo book named `*.kepub.epub` presents extension `epub`, and an
    // extension-less volume id presents `""`; both must reach the Kobo handler
    // via the top-level dispatcher because a Kobo DB was supplied.
    for ext in ["epub", ""] {
        let book = crate::decrypt(&kepub, ext, &keys).unwrap();
        assert_eq!(book.extension, "epub");
        assert_eq!(member(&book.data, XHTML_PATH), XHTML_PLAIN);
    }
}
