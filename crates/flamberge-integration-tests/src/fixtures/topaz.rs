//! Topaz `TPZ0` fixture (§5).
//!
//! Assembles a `TPZ0` container with a `dkey` record (the book key wrapped under
//! the PID via the Topaz cipher), an uncompressed and a zlib-compressed encrypted
//! page, and a `metadata` record carrying the title. Decryption (§5.4): the PID
//! decrypts the dkey sub-record to recover the book key, which then decrypts each
//! page (`-index-1` marks a record encrypted).
//!
//! Mirrors the `topaz.rs` unit-test fixture. The Topaz encoded-number and
//! length-prefixed-string encoders are private to that scheme, so they are
//! reimplemented here (they are the inverse of the public
//! `flamberge_formats::topaz_container::read_encoded_number`). No real book is
//! embedded (see [`crate::fixtures`]).

use flamberge_crypto::topaz::TopazCipher;
use flamberge_schemes::KeyStore;

use super::zlib;

const KEY_LEN: usize = 8;
const DKEY_SUBRECORD_LEN: usize = 24;
const PID: [u8; KEY_LEN] = *b"12345678";
const BOOK_KEY: [u8; KEY_LEN] = *b"BOOKKEY!";

/// A synthesized Topaz book plus the keys to decrypt it.
pub struct TopazFixture {
    /// The `TPZ0` file, for `flamberge_schemes::decrypt(_, "tpz", _)`.
    pub file: Vec<u8>,
    /// A `KeyStore` carrying the correct PID.
    pub keys: KeyStore,
    /// A `KeyStore` with a wrong PID, for the negative test.
    pub wrong_keys: KeyStore,
    /// Expected recovered plaintext of the uncompressed page.
    pub plain0: &'static [u8],
    /// Expected recovered plaintext of the compressed page.
    pub plain1: &'static [u8],
    /// Expected recovered book title.
    pub title: &'static str,
}

/// Encode an integer as a Topaz encoded-number (inverse of `read_encoded_number`).
fn encode_number(n: i64) -> Vec<u8> {
    let mut out = Vec::new();
    if n < 0 {
        out.push(0xFF);
    }
    let magnitude = n.unsigned_abs();
    if magnitude < 0x80 {
        out.push(magnitude as u8);
        return out;
    }
    let mut groups = Vec::new();
    let mut v = magnitude;
    while v > 0 {
        groups.push((v & 0x7F) as u8);
        v >>= 7;
    }
    groups.reverse();
    if n > 0 && groups[0] == 0x7F {
        groups.insert(0, 0x00);
    }
    let last = groups.len() - 1;
    for (i, group) in groups.iter().enumerate() {
        out.push(if i < last { group | 0x80 } else { *group });
    }
    out
}

/// Encode a length-prefixed string: encoded-number length then raw bytes.
fn encode_lp_string(s: &[u8]) -> Vec<u8> {
    let mut out = encode_number(s.len() as i64);
    out.extend_from_slice(s);
    out
}

/// A dkey sub-record encrypted under `pid` embedding `book_key`.
fn dkey_subrecord(pid: &[u8; KEY_LEN], book_key: &[u8; KEY_LEN]) -> Vec<u8> {
    let mut sub = Vec::new();
    sub.extend_from_slice(b"PID");
    sub.push(8);
    sub.extend_from_slice(pid);
    sub.push(8);
    sub.extend_from_slice(book_key);
    sub.extend_from_slice(b"pid");
    assert_eq!(sub.len(), DKEY_SUBRECORD_LEN);
    TopazCipher::new(pid).encrypt(&sub)
}

/// One payload record body: `lp(name) | encoded-index | stored-bytes`, index
/// negated (`-index-1`) when the record is encrypted.
fn payload_record(name: &[u8], index: usize, encrypted: bool, stored: &[u8]) -> Vec<u8> {
    let mut out = encode_lp_string(name);
    let stored_index = if encrypted {
        -(index as i64) - 1
    } else {
        index as i64
    };
    out.extend_from_slice(&encode_number(stored_index));
    out.extend_from_slice(stored);
    out
}

/// A page record whose plaintext is `content`, Topaz-encrypted under `BOOK_KEY`
/// and optionally zlib-compressed first. Returns `(stored, decompressed_len,
/// compressed_len)`.
fn encrypted_page(content: &[u8], compressed: bool) -> (Vec<u8>, u64, u64) {
    let staged = if compressed {
        zlib(content)
    } else {
        content.to_vec()
    };
    let stored = TopazCipher::new(&BOOK_KEY).encrypt(&staged);
    let decompressed_len = content.len() as u64;
    let compressed_len = if compressed { stored.len() as u64 } else { 0 };
    (stored, decompressed_len, compressed_len)
}

type FixtureRecord<'a> = (&'a [u8], Vec<(u64, u64)>, Vec<u8>);

/// Assemble a `TPZ0` file from records laid out consecutively in the payload.
fn build_file(records: &[FixtureRecord]) -> Vec<u8> {
    let mut payload = Vec::new();
    let mut offsets = Vec::new();
    for (_, _, body) in records {
        offsets.push(payload.len() as u64);
        payload.extend_from_slice(body);
    }

    let mut header = encode_number(records.len() as i64);
    for (i, (name, entries, _)) in records.iter().enumerate() {
        header.push(0x63);
        header.extend_from_slice(&encode_lp_string(name));
        header.extend_from_slice(&encode_number(entries.len() as i64));
        let mut entry_offset = offsets[i];
        for (decompressed_len, compressed_len) in entries {
            header.extend_from_slice(&encode_number(entry_offset as i64));
            header.extend_from_slice(&encode_number(*decompressed_len as i64));
            header.extend_from_slice(&encode_number(*compressed_len as i64));
            let stored = if *compressed_len > 0 {
                *compressed_len
            } else {
                *decompressed_len
            };
            entry_offset += stored;
        }
    }

    let mut file = Vec::new();
    file.extend_from_slice(b"TPZ0");
    file.extend_from_slice(&header);
    file.push(0x64);
    file.extend_from_slice(&payload);
    file
}

fn metadata_record(pairs: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut body = encode_lp_string(b"metadata");
    body.push(0x00);
    body.push(pairs.len() as u8);
    for (k, v) in pairs {
        body.extend_from_slice(&encode_lp_string(k));
        body.extend_from_slice(&encode_lp_string(v));
    }
    body
}

/// Build the Topaz fixture.
pub fn fixture() -> TopazFixture {
    let plain0: &[u8] = b"Topaz secret record contents.";
    let plain1: &[u8] = b"Second, compressed and encrypted, record body.";

    let dkey_blob = {
        let sub = dkey_subrecord(&PID, &BOOK_KEY);
        let mut blob = vec![1u8, sub.len() as u8];
        blob.extend_from_slice(&sub);
        blob
    };
    let dkey_len = dkey_blob.len() as u64;
    let dkey_body = payload_record(b"dkey", 0, false, &dkey_blob);

    let (page0, dl0, cl0) = encrypted_page(plain0, false);
    let (page1, dl1, cl1) = encrypted_page(plain1, true);
    let page0_body = payload_record(b"page0", 0, true, &page0);
    let page1_body = payload_record(b"page1", 0, true, &page1);

    let meta_body = metadata_record(&[(b"Title", b"Topaz Test Book")]);

    let file = build_file(&[
        (b"metadata", vec![(0, 0)], meta_body),
        (b"dkey", vec![(dkey_len, 0)], dkey_body),
        (b"page0", vec![(dl0, cl0)], page0_body),
        (b"page1", vec![(dl1, cl1)], page1_body),
    ]);

    TopazFixture {
        file,
        keys: KeyStore {
            pids: vec!["12345678".to_owned()],
            ..KeyStore::default()
        },
        wrong_keys: KeyStore {
            pids: vec!["WRONGPID".to_owned()],
            ..KeyStore::default()
        },
        plain0,
        plain1,
        title: "Topaz Test Book",
    }
}
