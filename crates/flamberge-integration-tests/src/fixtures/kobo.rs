//! Kobo KEPUB fixture (§9).
//!
//! Unlike the other schemes, Kobo's per-file page keys live *outside* the book,
//! in the Kobo library SQLite DB. This builds both: a KEPUB whose
//! `OEBPS/text.xhtml` member is two-layer-encrypted (`AES-ECB(page_key,
//! pkcs7(plain))`, with `page_key` itself `AES-ECB(user_key, page_key)`-wrapped),
//! and a minimal `KoboReader.sqlite` holding the base64 wrapped page key in
//! `content_keys` and the title in `content`. The decryptor derives candidate
//! user keys, unwraps the page key from the DB, and decrypts the member.
//!
//! Mirrors `kobo/tests.rs`, using only public APIs. No real book is embedded
//! (see [`crate::fixtures`]).

use std::io::{Cursor, Write};

use base64::Engine;
use flamberge_crypto::aes;
use flamberge_keys::kobo::derive_userkeys;
use flamberge_schemes::KeyStore;
use rusqlite::{params, Connection};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

use super::pkcs7_pad;

const VOLUME_ID: &str = "vol-1";
const XHTML_PATH: &str = "OEBPS/text.xhtml";
const XHTML_PLAIN: &[u8] = b"<?xml version=\"1.0\"?><html><body>hi</body></html>";
const PLAIN_PATH: &str = "OEBPS/notes.txt";
const PLAIN_CONTENT: &[u8] = b"this file is not encrypted";

/// A synthesized Kobo book plus the keys (and external DB) to decrypt it.
pub struct KoboFixture {
    /// The KEPUB archive, for `flamberge_schemes::decrypt(_, "kepub", _)`.
    pub kepub: Vec<u8>,
    /// A `KeyStore` carrying candidate user keys and the library DB bytes.
    pub keys: KeyStore,
    /// A `KeyStore` with a present-but-wrong user key (and the DB), for the
    /// negative test — so the scheme's per-key unwrap + `content::check`
    /// validation actually runs and rejects, rather than short-circuiting on an
    /// empty key list.
    pub wrong_keys: KeyStore,
    /// The encrypted member's path.
    pub xhtml_path: &'static str,
    /// Expected recovered plaintext of the encrypted member.
    pub expected_xhtml: &'static [u8],
    /// A DRM-free member's path (preserved verbatim).
    pub plain_path: &'static str,
    /// Expected bytes of the DRM-free member.
    pub expected_plain: &'static [u8],
    /// Expected recovered book title.
    pub title: &'static str,
}

/// Candidate user keys; the first is the one used to encrypt the fixture.
fn candidate_keys() -> Vec<[u8; 16]> {
    let macs = vec!["00:11:22:33:44:55".to_string(), "N9999999999".to_string()];
    let users = vec!["11111111-2222-3333-4444-555555555555".to_string()];
    derive_userkeys(&macs, &users)
}

/// Build `(kepub_bytes, sqlite_bytes)` for the given user key.
fn build(user_key: &[u8; 16]) -> (Vec<u8>, Vec<u8>) {
    let page_key = [0x5au8; 16];
    let wrapped = aes::ecb_encrypt(user_key, &page_key).unwrap();
    let elementkey_b64 = base64::engine::general_purpose::STANDARD.encode(&wrapped);
    let ciphertext = aes::ecb_encrypt(&page_key, &pkcs7_pad(XHTML_PLAIN, 16)).unwrap();

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

/// Build the Kobo fixture.
pub fn fixture() -> KoboFixture {
    let candidates = candidate_keys();
    let (kepub, sqlite) = build(&candidates[0]);

    let keys = KeyStore {
        kobo_keys: candidates,
        kobo_db: Some(sqlite.clone()),
        ..KeyStore::default()
    };
    // A present-but-wrong user key: the scheme unwraps a bad page key, decrypts
    // the member to garbage, and `content::check` rejects it — exercising real
    // wrong-key rejection rather than the empty-key short-circuit.
    let wrong_keys = KeyStore {
        kobo_keys: vec![[0xABu8; 16]],
        kobo_db: Some(sqlite),
        ..KeyStore::default()
    };

    KoboFixture {
        kepub,
        keys,
        wrong_keys,
        xhtml_path: XHTML_PATH,
        expected_xhtml: XHTML_PLAIN,
        plain_path: PLAIN_PATH,
        expected_plain: PLAIN_CONTENT,
        title: "Test Book",
    }
}
