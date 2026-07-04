//! eReader `.pdb` fixture (§8).
//!
//! Builds a version-260 eReader Palm database whose DRM layout mirrors
//! `erdr2pml.py` in reverse: text pages are `DES-ECB(fixKey(content_key),
//! pad8(zlib(text)))`; the DRM cookie in record 1 stores `DES-ECB(fixKey(
//! user_key), content_key)` plus a SHA-1 check, is scrambled by the header
//! `unshuff` permutation (inverted here), and is itself `DES-ECB`-encrypted under
//! record 1's own first ciphertext block. The decryptor recovers `content_key`
//! from the cookie using the user key, then inflates each page into PML.
//!
//! Mirrors the version-260 case of `ereader/tests.rs`; the version-272
//! footnote/sidebar variant depends on scheme-private helpers (`de_xor`) and is
//! already covered by that scheme's unit tests. No real book is embedded (see
//! [`crate::fixtures`]).

use std::io::Write;

use flamberge_crypto::{des, digest};
use flamberge_keys::ereader::user_key as gen_user_key;
use flamberge_schemes::KeyStore;

/// A synthesized eReader book plus the keys to decrypt it.
pub struct EreaderFixture {
    /// The `.pdb` image, for `flamberge_schemes::decrypt(_, "pdb", _)`.
    pub pdb: Vec<u8>,
    /// A `KeyStore` carrying the correct 8-byte user key.
    pub keys: KeyStore,
    /// A `KeyStore` with a wrong user key, for the negative test.
    pub wrong_keys: KeyStore,
    /// The PML member name inside the output `.pmlz`.
    pub pml_name: &'static str,
    /// Expected recovered PML (high bytes escaped as `\aNNN`).
    pub expected_pml: &'static [u8],
    /// The image member name inside the output `.pmlz`.
    pub image_name: &'static str,
    /// Expected recovered image bytes.
    pub expected_image: &'static [u8],
    /// Expected recovered book title.
    pub title: &'static str,
}

fn put16(v: &mut [u8], off: usize, x: u16) {
    v[off..off + 2].copy_from_slice(&x.to_be_bytes());
}
fn put32(v: &mut [u8], off: usize, x: u32) {
    v[off..off + 4].copy_from_slice(&x.to_be_bytes());
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn pad8(mut v: Vec<u8>) -> Vec<u8> {
    while v.len() % 8 != 0 {
        v.push(0);
    }
    v
}

/// Encrypt a page as an eReader file stores it: zlib, pad to the DES block, then
/// DES-ECB with `fixKey(content_key)`.
fn enc_page(content_key: &[u8; 8], text: &[u8]) -> Vec<u8> {
    des::ecb_encrypt(&des::fix_key(content_key), &pad8(zlib(text))).unwrap()
}

/// Build record 1 (first text page + DRM cookie) for a version-260, sub-13 book.
fn build_record1(content_key: &[u8; 8], user_key: &[u8; 8], text0: &[u8]) -> Vec<u8> {
    const SUB_VERSION: u16 = 13;
    const NUM_TEXT_PAGES: u16 = 2;
    const FIRST_IMAGE_PAGE: u16 = 3;
    const NUM_IMAGE_PAGES: u16 = 1;
    const COOKIE_SIZE: usize = 0xf0;
    const COOKIE_SHUF: u32 = 5;
    // (260, 13) key/SHA offsets within the cookie header.
    const KEY_OFF: usize = 44;
    const SHA_OFF: usize = 52;

    let ct_text = enc_page(content_key, text0);
    assert!(ct_text.len() >= 8, "text page too short for cookie key");
    let cookie_key = des::fix_key(&ct_text[0..8]);

    let hlen = COOKIE_SIZE - 8;
    let mut r = vec![0u8; hlen];
    put16(&mut r, 0, SUB_VERSION);
    put16(&mut r, 2, NUM_TEXT_PAGES + 1);
    put32(&mut r, 4, (1 << 9) | (1 << 7) | (1 << 10));
    put16(&mut r, 24, FIRST_IMAGE_PAGE);
    put16(&mut r, 26, NUM_IMAGE_PAGES);

    let encrypted_key = des::ecb_encrypt(&des::fix_key(user_key), content_key).unwrap();
    r[KEY_OFF..KEY_OFF + 8].copy_from_slice(&encrypted_key);
    r[SHA_OFF..SHA_OFF + 20].copy_from_slice(&digest::sha1(content_key));

    // Invert `unshuff`: with gcd(shuf, hlen) == 1 the scatter is a bijection, so
    // `pre[i] = r[j]` reproduces the exact permutation the parser reverses.
    let shuf = COOKIE_SHUF as usize;
    let mut pre = vec![0u8; hlen];
    let mut j = 0usize;
    for slot in pre.iter_mut() {
        j = (j + shuf) % hlen;
        *slot = r[j];
    }
    let mut input = pre;
    input.extend_from_slice(&COOKIE_SHUF.to_be_bytes());
    input.extend_from_slice(&(COOKIE_SIZE as u32).to_be_bytes());

    let cookie_region = des::ecb_encrypt(&cookie_key, &input).unwrap();
    let mut record1 = ct_text;
    record1.extend_from_slice(&cookie_region);
    record1
}

fn build_pdb(magic: &[u8; 8], name: &[u8], records: &[Vec<u8>]) -> Vec<u8> {
    let n = records.len();
    let table_end = 78 + n * 8;
    let mut out = vec![0u8; table_end];
    let nlen = name.len().min(31);
    out[..nlen].copy_from_slice(&name[..nlen]);
    out[0x3C..0x3C + 8].copy_from_slice(magic);
    put16(&mut out, 0x4C, n as u16);

    let mut offset = table_end;
    for (i, rec) in records.iter().enumerate() {
        put32(&mut out, 78 + i * 8, offset as u32);
        offset += rec.len();
    }
    for rec in records {
        out.extend_from_slice(rec);
    }
    out
}

fn image_record(name: &str, body: &[u8]) -> Vec<u8> {
    let mut rec = vec![0u8; 62];
    rec[4..4 + name.len()].copy_from_slice(name.as_bytes());
    rec.extend_from_slice(body);
    rec
}

fn version_record(version: u16) -> Vec<u8> {
    let mut v = vec![0u8; 8];
    put16(&mut v, 0, version);
    v
}

/// Build the version-260 eReader fixture.
pub fn fixture() -> EreaderFixture {
    let user_key = gen_user_key("Jane Doe", "4111 1111 1111 1111");
    let content_key = *b"CONTKEY!";

    // 0xE9 is 'é' in cp1252 — proves high-byte escaping (`\a233`) in the PML.
    let record1 = build_record1(&content_key, &user_key, b"Chapter 1. Caf\xe9 scene.");
    let text2 = enc_page(&content_key, b" The story continues.");
    let records = vec![
        version_record(260),
        record1,
        text2,
        image_record("cover.png", b"PNGIMAGEDATA"),
    ];
    let pdb = build_pdb(b"PNRdPPrs", b"MyBook", &records);

    let mut keys = KeyStore::new();
    keys.ereader_keys.push(user_key);
    let mut wrong_keys = KeyStore::new();
    wrong_keys
        .ereader_keys
        .push(gen_user_key("Wrong Name", "9999999999999999"));

    EreaderFixture {
        pdb,
        keys,
        wrong_keys,
        pml_name: "MyBook.pml",
        expected_pml: b"Chapter 1. Caf\\a233 scene. The story continues.",
        image_name: "images/cover.png",
        expected_image: b"PNGIMAGEDATA",
        title: "MyBook",
    }
}
