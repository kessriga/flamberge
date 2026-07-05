//! Adobe ADEPT and Barnes & Noble `EBX_HANDLER` PDF fixtures (§7.4 / §4.4).
//!
//! Builds a classic-xref PDF whose objects are RC4-enciphered with a per-object
//! MD5 key (`genkey_v2` for `/V 4`, `genkey_v3` for `/V 3`) and whose `/Encrypt`
//! dict carries an `ADEPT_LICENSE` = base64(deflate(`rights.xml`(base64(wrapped
//! book key)))). The two schemes differ only in how the book key is wrapped: RSA
//! for ADEPT (modulus-length ciphertext), zero-IV AES for B&N (48 bytes).
//!
//! Mirrors the `pdf_common.rs` unit-test fixtures, rebuilt on public APIs. No real
//! book is embedded (see [`crate::fixtures`]).

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use flamberge_crypto::{digest, rc4};
use flamberge_formats::pdf::PdfDocument;
use flamberge_schemes::KeyStore;
use rand::SeedableRng;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::RsaPrivateKey;

use super::{bn_wrap, raw_deflate, rights_xml, rsa_wrap_pkcs1, user_key_from_cchash, zlib};

/// A synthesized EBX_HANDLER PDF plus the keys to decrypt it.
pub struct PdfFixture {
    /// The encrypted PDF, for `flamberge_schemes::decrypt(_, "pdf", _)`.
    pub pdf: Vec<u8>,
    /// A `KeyStore` that recovers the book key.
    pub keys: KeyStore,
    /// A `KeyStore` that must fail, for the negative test.
    pub wrong_keys: KeyStore,
    /// Expected recovered obj-4 content-stream plaintext.
    pub page: Vec<u8>,
    /// Expected recovered obj-5 string.
    pub secret: Vec<u8>,
}

/// Per-object RC4 key, replicating `pdf_common::genkey_{v2,v3}` (private there).
fn genkey(version: u8, book_key: &[u8; 16], objid: u32, genno: u16) -> [u8; 16] {
    let mut buf = book_key.to_vec();
    if version == 3 {
        let o = (objid ^ 0x0035_69ac).to_le_bytes();
        let g = ((genno as u32) ^ 0x0000_ca96).to_le_bytes();
        buf.extend_from_slice(&[o[0], g[0], o[1], g[1], o[2]]);
        buf.extend_from_slice(b"sAlT");
    } else {
        buf.extend_from_slice(&objid.to_le_bytes()[..3]);
        buf.extend_from_slice(&genno.to_le_bytes()[..2]);
    }
    digest::md5(&buf)
}

/// RC4-encipher `data` for one object — the inverse of the scheme's decipher.
fn rc4_obj(book_key: &[u8; 16], version: u8, objid: u32, genno: u16, data: &[u8]) -> Vec<u8> {
    rc4::apply(&genkey(version, book_key, objid, genno), data)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The `ADEPT_LICENSE` string value: base64(deflate(-15, rights_xml(base64(wrapped)))).
fn adept_license_value(wrapped: &[u8]) -> String {
    let xml = rights_xml(&STANDARD.encode(wrapped));
    STANDARD.encode(raw_deflate(&xml))
}

/// Build a classic-xref EBX_HANDLER PDF (obj4 Flate content, obj5 hex string,
/// obj6 `/Encrypt`). `version` picks genkey v2/v3; `v_field` is the dict's `/V`.
fn build_ebx_pdf(
    book_key: &[u8; 16],
    version: u8,
    v_field: i64,
    license_b64: &str,
    page_text: &[u8],
    secret: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"%PDF-1.4\n");
    let mut off = [0usize; 7];

    off[1] = buf.len();
    buf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    off[2] = buf.len();
    buf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
    off[3] = buf.len();
    buf.extend_from_slice(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R /MediaBox [0 0 612 792] >>\nendobj\n",
    );

    let enc4 = rc4_obj(book_key, version, 4, 0, &zlib(page_text));
    off[4] = buf.len();
    buf.extend_from_slice(
        format!(
            "4 0 obj\n<< /Length {} /Filter /FlateDecode >>\nstream\n",
            enc4.len()
        )
        .as_bytes(),
    );
    buf.extend_from_slice(&enc4);
    buf.extend_from_slice(b"\nendstream\nendobj\n");

    let enc5 = rc4_obj(book_key, version, 5, 0, secret);
    off[5] = buf.len();
    buf.extend_from_slice(format!("5 0 obj\n<{}>\nendobj\n", hex(&enc5)).as_bytes());

    off[6] = buf.len();
    buf.extend_from_slice(
        format!(
            "6 0 obj\n<< /Filter /EBX_HANDLER /V {v_field} /Length 128 /ADEPT_LICENSE ({license_b64}) >>\nendobj\n"
        )
        .as_bytes(),
    );

    let xref_pos = buf.len();
    buf.extend_from_slice(b"xref\n0 7\n");
    buf.extend_from_slice(b"0000000000 65535 f \n");
    for &o in off.iter().skip(1) {
        buf.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    buf.extend_from_slice(b"trailer\n<< /Size 7 /Root 1 0 R /Encrypt 6 0 R >>\n");
    buf.extend_from_slice(format!("startxref\n{xref_pos}\n%%EOF").as_bytes());
    buf
}

/// Re-parse a decrypted PDF and pull back `(obj4 inflated content, obj5 string)`,
/// asserting the `/Encrypt` dict was stripped.
pub fn read_back(pdf: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let doc = PdfDocument::parse(pdf).unwrap();
    assert!(doc.encrypt().is_none(), "/Encrypt must be stripped");
    let content = doc.get_object(4).unwrap();
    let text = content.as_stream().unwrap().decoded().unwrap();
    let secret = doc.get_object(5).unwrap().as_str_bytes().unwrap().to_vec();
    (text, secret)
}

fn seeded_rsa() -> RsaPrivateKey {
    RsaPrivateKey::new(&mut rand::rngs::StdRng::seed_from_u64(0x1201), 1024).expect("keygen")
}

/// Build an ADEPT EBX_HANDLER PDF (`/V 4`, genkey_v2). The PKCS#1 DER RSA private
/// key goes in `adept_keys`.
pub fn adept() -> PdfFixture {
    let book_key = [0x9Cu8; 16];
    let key = seeded_rsa();
    let der = key.to_pkcs1_der().unwrap().as_bytes().to_vec();
    let license = adept_license_value(&rsa_wrap_pkcs1(&key, &book_key));
    let page = b"BT /F1 12 Tf (Chapter one, now readable.) Tj ET".to_vec();
    let secret = b"Secret /Info string, decrypted.".to_vec();
    let pdf = build_ebx_pdf(&book_key, 2, 4, &license, &page, &secret);

    let other = RsaPrivateKey::new(&mut rand::rngs::StdRng::seed_from_u64(0x9999), 1024)
        .unwrap()
        .to_pkcs1_der()
        .unwrap()
        .as_bytes()
        .to_vec();
    PdfFixture {
        pdf,
        keys: KeyStore {
            adept_keys: vec![der],
            ..KeyStore::default()
        },
        wrong_keys: KeyStore {
            adept_keys: vec![other],
            ..KeyStore::default()
        },
        page,
        secret,
    }
}

/// Build a B&N EBX_HANDLER PDF (`/V 4`, genkey_v2). The 28-char ccHash goes in
/// `bandn_keys`; the book key is wrapped with the user key (48-byte AES).
pub fn ignoble() -> PdfFixture {
    let book_key = [0x77u8; 16];
    let cchash =
        flamberge_keys::ignoble::generate_key("Ada Lovelace", "4111 1111 1111 1111").unwrap();
    let user_key = user_key_from_cchash(&cchash);
    let license = adept_license_value(&bn_wrap(&user_key, &book_key));
    let page = b"B&N page content".to_vec();
    let secret = b"B&N secret".to_vec();
    let pdf = build_ebx_pdf(&book_key, 2, 4, &license, &page, &secret);

    let wrong =
        flamberge_keys::ignoble::generate_key("Ada Lovelace", "4000 0000 0000 0002").unwrap();
    PdfFixture {
        pdf,
        keys: KeyStore {
            bandn_keys: vec![cchash],
            ..KeyStore::default()
        },
        wrong_keys: KeyStore {
            bandn_keys: vec![wrong],
            ..KeyStore::default()
        },
        page,
        secret,
    }
}
