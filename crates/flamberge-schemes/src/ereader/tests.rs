//! Round-trip tests for the eReader scheme, built on synthesized `.pdb`
//! fixtures. The builder mirrors `erdr2pml.py`'s DRM layout in reverse: encrypt
//! text with the content key, invert the header unshuffle, and DES-encrypt the
//! cookie with record 1's own first block as its key.

use std::io::{Read, Write};

use flamberge_crypto::{des, digest};
use flamberge_keys::ereader::user_key as gen_user_key;
use zip::ZipArchive;

use super::content::{clean_pml, de_xor};
use super::{decrypt, detect};
use crate::{KeyStore, SchemeError};

const XOR_OFF: usize = 8;
const XOR_SIZE: usize = 8;

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

/// Encrypt a page body the way a real eReader file stores it: zlib, pad to the
/// DES block, then DES-ECB with `fixKey(content_key)`.
fn enc_page(content_key: &[u8; 8], text: &[u8]) -> Vec<u8> {
    des::ecb_encrypt(&des::fix_key(content_key), &pad8(zlib(text))).unwrap()
}

fn key_offsets(version: u16, sub: u16) -> (usize, usize) {
    match (version, sub) {
        (259, 7) => (64, 44),
        (260, 13) => (44, 52),
        (260, 11) => (64, 44),
        (272, _) => (172, 56),
        _ => panic!("unhandled version/sub in test"),
    }
}

struct BookSpec {
    version: u16,
    sub_version: u16,
    num_text_pages: u16,
    first_image_page: u16,
    num_image_pages: u16,
    first_footnote_page: u16,
    num_footnote_pages: u16,
    first_sidebar_page: u16,
    num_sidebar_pages: u16,
    content_key: [u8; 8],
    user_key: [u8; 8],
    cookie_size: usize,
    cookie_shuf: u32,
}

/// Build record 1 (first text page + DRM cookie). Returns the record and its
/// leading ciphertext (from which the XOR table is later sliced).
fn build_record1(spec: &BookSpec, text0: &[u8]) -> Vec<u8> {
    let ct_text = enc_page(&spec.content_key, text0);
    assert!(
        ct_text.len() >= XOR_OFF + XOR_SIZE,
        "text page too short for xor table"
    );
    let cookie_key = des::fix_key(&ct_text[0..8]);

    let hlen = spec.cookie_size - 8;
    let mut r = vec![0u8; hlen];
    put16(&mut r, 0, spec.sub_version);
    put16(&mut r, 2, spec.num_text_pages + 1);
    put32(&mut r, 4, (1 << 9) | (1 << 7) | (1 << 10));
    put16(&mut r, 24, spec.first_image_page);
    put16(&mut r, 26, spec.num_image_pages);
    if spec.version == 272 {
        put16(&mut r, 44, spec.first_footnote_page);
        put16(&mut r, 46, spec.num_footnote_pages);
        put16(&mut r, 36, spec.first_sidebar_page);
        put16(&mut r, 38, spec.num_sidebar_pages);
        put16(&mut r, 40, XOR_OFF as u16);
        put16(&mut r, 42, XOR_SIZE as u16);
    }

    let (key_off, sha_off) = key_offsets(spec.version, spec.sub_version);
    let encrypted_key = des::ecb_encrypt(&des::fix_key(&spec.user_key), &spec.content_key).unwrap();
    r[key_off..key_off + 8].copy_from_slice(&encrypted_key);
    r[sha_off..sha_off + 20].copy_from_slice(&digest::sha1(&spec.content_key));

    // Invert `unshuff`: with gcd(shuf, hlen) == 1 the scatter is a bijection, so
    // `pre[i] = r[j]` reproduces the exact permutation the parser reverses.
    let shuf = spec.cookie_shuf as usize;
    let mut pre = vec![0u8; hlen];
    let mut j = 0usize;
    for slot in pre.iter_mut() {
        j = (j + shuf) % hlen;
        *slot = r[j];
    }
    let mut input = pre;
    input.extend_from_slice(&spec.cookie_shuf.to_be_bytes());
    input.extend_from_slice(&(spec.cookie_size as u32).to_be_bytes());

    let cookie_region = des::ecb_encrypt(&cookie_key, &input).unwrap();
    let mut record1 = ct_text;
    record1.extend_from_slice(&cookie_region);
    record1
}

/// A footnote/sidebar id record: `[2 pad][len][id][1 pad]` per entry, obscured
/// through the XOR table (same op the parser uses to recover it).
fn build_id_record(table: &[u8], id: &[u8]) -> Vec<u8> {
    let mut plain = vec![0u8, 0u8, id.len() as u8];
    plain.extend_from_slice(id);
    plain.push(0);
    de_xor(&plain, 0, table)
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

fn read_pmlz(archive: &[u8], name: &str) -> Vec<u8> {
    let mut zip = ZipArchive::new(std::io::Cursor::new(archive.to_vec())).unwrap();
    let mut f = zip.by_name(name).unwrap();
    let mut out = Vec::new();
    f.read_to_end(&mut out).unwrap();
    out
}

// ---------------------------------------------------------------------------

#[test]
fn de_xor_is_self_inverse() {
    let table = b"\x11\x22\x33\x44";
    let plain = b"footnote id string";
    let coded = de_xor(plain, 0, table);
    assert_ne!(&coded[..], &plain[..]);
    assert_eq!(de_xor(&coded, 0, table), plain);
}

#[test]
fn de_xor_empty_table_is_noop() {
    assert_eq!(de_xor(b"abc", 0, b""), b"abc");
}

#[test]
fn clean_pml_escapes_high_bytes_only() {
    // 'e' + é(0xE9) + '!' -> ASCII passes through, 0xE9 -> \a233
    assert_eq!(clean_pml(b"e\xe9!"), b"e\\a233!");
    assert_eq!(clean_pml(b"\x80\xff"), b"\\a128\\a255");
}

#[test]
fn decrypts_v260_pdb_through_dispatch() {
    let user_key = gen_user_key("Jane Doe", "4111 1111 1111 1111");
    // Interlock check: this is exactly what `flamberge keys ereader
    // --name "Jane Doe" --cc "4111 1111 1111 1111"` prints, so a `.pdb` built
    // for this key is decryptable through the real CLI's `--ereader-key` path.
    assert_eq!(user_key, [0xcb, 0x9b, 0x5f, 0x74, 0x8b, 0x8b, 0x70, 0xb9]);
    let spec = BookSpec {
        version: 260,
        sub_version: 13,
        num_text_pages: 2,
        first_image_page: 3,
        num_image_pages: 1,
        first_footnote_page: 0,
        num_footnote_pages: 0,
        first_sidebar_page: 0,
        num_sidebar_pages: 0,
        content_key: *b"CONTKEY!",
        user_key,
        cookie_size: 0xf0,
        cookie_shuf: 5,
    };
    // 0xE9 is 'é' in cp1252 — proves high-byte escaping in the final PML.
    let record1 = build_record1(&spec, b"Chapter 1. Caf\xe9 scene.");
    let text2 = enc_page(&spec.content_key, b" The story continues.");
    let records = vec![
        version_record(260),
        record1,
        text2,
        image_record("cover.png", b"PNGIMAGEDATA"),
    ];
    let pdb = build_pdb(b"PNRdPPrs", b"MyBook", &records);

    let mut keys = KeyStore::new();
    keys.ereader_keys.push(user_key);
    let book = crate::decrypt(&pdb, "pdb", &keys).unwrap();

    assert_eq!(book.extension, "pmlz");
    assert_eq!(book.title.as_deref(), Some("MyBook"));

    let pml = read_pmlz(&book.data, "MyBook.pml");
    assert_eq!(pml, b"Chapter 1. Caf\\a233 scene. The story continues.");
    assert_eq!(read_pmlz(&book.data, "images/cover.png"), b"PNGIMAGEDATA");
}

#[test]
fn decrypts_v272_with_footnote_and_sidebar() {
    let user_key = gen_user_key("Reader", "1234567812345678");
    let spec = BookSpec {
        version: 272,
        sub_version: 0,
        num_text_pages: 1,
        first_image_page: 0,
        num_image_pages: 0,
        first_footnote_page: 2,
        num_footnote_pages: 2,
        first_sidebar_page: 4,
        num_sidebar_pages: 2,
        content_key: *b"272CKEY!",
        user_key,
        cookie_size: 0x100,
        cookie_shuf: 5,
    };
    let record1 = build_record1(&spec, b"Body text with a note.");
    let table = record1[XOR_OFF..XOR_OFF + XOR_SIZE].to_vec();

    let records = vec![
        version_record(272),
        record1,
        build_id_record(&table, b"fn1"),
        enc_page(&spec.content_key, b"A footnote."),
        build_id_record(&table, b"sb1"),
        enc_page(&spec.content_key, b"A sidebar."),
    ];
    let pdb = build_pdb(b"PNRdPPrs", b"Notes", &records);

    let mut keys = KeyStore::new();
    keys.ereader_keys.push(user_key);
    let book = crate::decrypt(&pdb, "pdb", &keys).unwrap();

    let pml = String::from_utf8(read_pmlz(&book.data, "Notes.pml")).unwrap();
    assert_eq!(
        pml,
        "Body text with a note.\n\
         <footnote id=\"fn1\">\nA footnote.\n</footnote>\n\n\
         <sidebar id=\"sb1\">\nA sidebar.\n</sidebar>\n"
    );
}

#[test]
fn wrong_key_reports_no_key_worked() {
    let user_key = gen_user_key("Jane Doe", "4111111111111111");
    let spec = BookSpec {
        version: 260,
        sub_version: 13,
        num_text_pages: 1,
        first_image_page: 0,
        num_image_pages: 0,
        first_footnote_page: 0,
        num_footnote_pages: 0,
        first_sidebar_page: 0,
        num_sidebar_pages: 0,
        content_key: *b"CONTKEY!",
        user_key,
        cookie_size: 0xf0,
        cookie_shuf: 5,
    };
    let record1 = build_record1(&spec, b"Some text.");
    let pdb = build_pdb(b"PNRdPPrs", b"Book", &[version_record(260), record1]);

    let mut keys = KeyStore::new();
    keys.ereader_keys
        .push(gen_user_key("Wrong Name", "9999999999999999"));
    assert!(matches!(
        decrypt(&pdb, &keys),
        Err(SchemeError::NoKeyWorked)
    ));

    // No keys at all is also NoKeyWorked, not a panic.
    assert!(matches!(
        decrypt(&pdb, &KeyStore::new()),
        Err(SchemeError::NoKeyWorked)
    ));
}

#[test]
fn non_ereader_palmdb_falls_through() {
    let pdb = build_pdb(b"BOOKMOBI", b"AMobiBook", &[vec![0u8; 8], vec![0u8; 8]]);
    assert!(!detect(&pdb));
    assert!(matches!(
        decrypt(&pdb, &KeyStore::new()),
        Err(SchemeError::NotThisScheme)
    ));
}
