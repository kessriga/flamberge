//! Adobe ADEPT (§7.3) and Barnes & Noble (§4.4) EPUB fixtures.
//!
//! Both schemes package an OCF EPUB identically — a `mimetype`-stored ZIP with
//! `META-INF/rights.xml` (the base64 wrapped book key) and
//! `META-INF/encryption.xml` (the list of encrypted members), each encrypted
//! member being `IV || AES-128-CBC(book_key, IV, pkcs7(body))`. They differ only
//! in how the book key is wrapped in `rights.xml`:
//!
//! * ADEPT wraps it with the user's RSA public key (PKCS#1 v1.5), 172 base64 chars.
//! * B&N wraps it with AES-128-CBC under the user key (`0xAA*16 || book_key`),
//!   64 base64 chars, book key = last 16 plaintext bytes.
//!
//! Mirrors the `adept.rs` / `ignoble.rs` unit-test fixtures, rebuilt on public
//! APIs. No real book is embedded (see [`crate::fixtures`]).

use base64::Engine;
use flamberge_crypto::aes;
use flamberge_formats::ocf;
use flamberge_schemes::KeyStore;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPrivateKey};

use super::{pkcs7_pad, raw_deflate};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// `(member path, bytes)` pairs — either ZIP members to build or expected plaintext.
type NamedBytes = Vec<(&'static str, Vec<u8>)>;

/// A synthesized ADEPT/B&N EPUB plus the keys to decrypt it.
pub struct EpubFixture {
    /// The encrypted `.epub` bytes, ready for `flamberge_schemes::decrypt(_, "epub", _)`.
    pub epub: Vec<u8>,
    /// A `KeyStore` that recovers the book.
    pub keys: KeyStore,
    /// A `KeyStore` that must fail (wrong user key), for the negative test.
    pub wrong_keys: KeyStore,
    /// `(member path, expected recovered plaintext)` for the encrypted members.
    pub decrypted_members: NamedBytes,
}

/// Encrypt one member as ADEPT/B&N store it: `IV || AES-CBC(book_key, IV,
/// pkcs7(body))`, `body` raw-deflated when `deflate`. The prepended IV block is
/// what the decryptor drops (§4.4/§7.3).
fn encrypt_member(book_key: &[u8; 16], content: &[u8], deflate: bool) -> Vec<u8> {
    let body = if deflate {
        raw_deflate(content)
    } else {
        content.to_vec()
    };
    let iv = [0x5Au8; 16];
    let ct = aes::cbc_encrypt(book_key, &iv, &pkcs7_pad(&body, 16)).unwrap();
    let mut out = iv.to_vec();
    out.extend_from_slice(&ct);
    out
}

/// A minimal `rights.xml` carrying the base64 wrapped book key.
fn rights_xml(key_b64: &str) -> Vec<u8> {
    const ADEPT_NS: &str = "http://ns.adobe.com/adept";
    format!(
        "<?xml version=\"1.0\"?>\
         <adept:rights xmlns:adept=\"{ADEPT_NS}\">\
         <adept:licenseToken><adept:encryptedKey>{key_b64}</adept:encryptedKey>\
         </adept:licenseToken></adept:rights>"
    )
    .into_bytes()
}

/// An `encryption.xml` listing each encrypted member path.
fn encryption_xml(paths: &[&str]) -> Vec<u8> {
    const ENC_NS: &str = "http://www.w3.org/2001/04/xmlenc#";
    let mut body = format!("<encryption xmlns:enc=\"{ENC_NS}\">");
    for p in paths {
        body.push_str(&format!(
            "<enc:EncryptedData><enc:CipherData>\
             <enc:CipherReference URI=\"{p}\"/>\
             </enc:CipherData></enc:EncryptedData>"
        ));
    }
    body.push_str("</encryption>");
    body.into_bytes()
}

/// The two encrypted members (deflated chapter + stored CSS) plus one verbatim
/// member, common to both schemes. Returns `(zip members, expected plaintext)`.
fn epub_members(content_key: &[u8; 16], wrapped_b64: &str) -> (NamedBytes, NamedBytes) {
    let chapter = b"<html><body>Chapter one, now readable.</body></html>".to_vec();
    let css = b"body { color: black; }".to_vec();
    let members = vec![
        ("mimetype", b"application/epub+zip".to_vec()),
        (ocf::RIGHTS_XML, rights_xml(wrapped_b64)),
        (
            ocf::ENCRYPTION_XML,
            encryption_xml(&["OEBPS/ch1.html", "OEBPS/style.css"]),
        ),
        // Deflated then encrypted (the common case).
        (
            "OEBPS/ch1.html",
            encrypt_member(content_key, &chapter, true),
        ),
        // Stored (not deflated) then encrypted — exercises inflate pass-through.
        ("OEBPS/style.css", encrypt_member(content_key, &css, false)),
        // An unencrypted member copied through verbatim.
        ("OEBPS/content.opf", b"<package/>".to_vec()),
    ];
    let expected = vec![("OEBPS/ch1.html", chapter), ("OEBPS/style.css", css)];
    (members, expected)
}

// --- ADEPT ---------------------------------------------------------------

/// Textbook RSA public op (`m^e mod n`) to wrap a block — inverse of the
/// scheme's private decrypt.
fn rsa_wrap(key: &RsaPrivateKey, block: &[u8]) -> Vec<u8> {
    let c = BigUint::from_bytes_be(block).modpow(key.e(), key.n());
    let raw = c.to_bytes_be();
    let mut out = vec![0u8; key.size() - raw.len()];
    out.extend_from_slice(&raw);
    out
}

/// A PKCS#1 v1.5 encryption block `00 02 <FF padding> 00 <payload>`.
fn pkcs1_block(modulus_bytes: usize, payload: &[u8]) -> Vec<u8> {
    let mut b = vec![0x00, 0x02];
    b.extend(std::iter::repeat_n(
        0xFFu8,
        modulus_bytes - payload.len() - 3,
    ));
    b.push(0x00);
    b.extend_from_slice(payload);
    b
}

/// A reproducible RSA key (seeded so the wrong-key `[-17]` check is deterministic).
fn rsa_key(seed: u64) -> RsaPrivateKey {
    RsaPrivateKey::new(&mut StdRng::seed_from_u64(seed), 1024).expect("keygen")
}

/// Build an ADEPT EPUB (§7.3): a fresh 1024-bit RSA key wraps `content_key`; the
/// PKCS#1 DER private key goes in `adept_keys`.
pub fn adept() -> EpubFixture {
    let content_key = [0x9Cu8; 16];
    let key = rsa_key(1);
    let der = key.to_pkcs1_der().unwrap().as_bytes().to_vec();

    let wrapped = rsa_wrap(&key, &pkcs1_block(key.size(), &content_key));
    let wrapped_b64 = B64.encode(&wrapped);
    assert_eq!(
        wrapped_b64.len(),
        ocf::ADEPT_KEY_LEN,
        "wrapped key must be 172 chars"
    );

    let (members, decrypted_members) = epub_members(&content_key, &wrapped_b64);
    let epub = super::build_zip(&members);

    // An independent RSA key can't unwrap the book key (wrong-key signal).
    let other = rsa_key(999).to_pkcs1_der().unwrap().as_bytes().to_vec();
    EpubFixture {
        epub,
        keys: KeyStore {
            adept_keys: vec![der],
            ..KeyStore::default()
        },
        wrong_keys: KeyStore {
            adept_keys: vec![other],
            ..KeyStore::default()
        },
        decrypted_members,
    }
}

// --- Barnes & Noble ------------------------------------------------------

/// The first 16 bytes of the base64-decoded ccHash — the AES user key.
fn user_key_from_cchash(cchash: &str) -> [u8; 16] {
    let raw = B64.decode(cchash).unwrap();
    let mut k = [0u8; 16];
    k.copy_from_slice(&raw[..16]);
    k
}

/// Wrap the book key as B&N stores it: `AES-128-CBC(user_key, 0, pkcs7(0xAA*16
/// || book_key))`, base64 (64 chars). The book key is the last 16 plaintext bytes.
fn wrap_book_key(user_key: &[u8; 16], book_key: &[u8; 16]) -> String {
    let mut plain = vec![0xAAu8; 16];
    plain.extend_from_slice(book_key);
    let wrapped = aes::cbc_encrypt(user_key, &[0u8; 16], &pkcs7_pad(&plain, 16)).unwrap();
    let b64 = B64.encode(&wrapped);
    assert_eq!(b64.len(), ocf::BN_KEY_LEN, "wrapped key must be 64 chars");
    b64
}

/// Build a B&N EPUB (§4.4): the user key is derived from `flamberge_keys::ignoble`
/// (name + credit card), and the 28-char ccHash goes in `bandn_keys`.
pub fn ignoble() -> EpubFixture {
    let content_key = [0x9Cu8; 16];
    let cchash = flamberge_keys::ignoble::generate_key("Ada Lovelace", "4111 1111 1111 1111")
        .expect("keygen");
    let user_key = user_key_from_cchash(&cchash);
    let wrapped_b64 = wrap_book_key(&user_key, &content_key);

    let (members, decrypted_members) = epub_members(&content_key, &wrapped_b64);
    let epub = super::build_zip(&members);

    // A ccHash from a different card yields a different user key → wrong key.
    let wrong =
        flamberge_keys::ignoble::generate_key("Ada Lovelace", "4000 0000 0000 0002").unwrap();
    EpubFixture {
        epub,
        keys: KeyStore {
            bandn_keys: vec![cchash],
            ..KeyStore::default()
        },
        wrong_keys: KeyStore {
            bandn_keys: vec![wrong],
            ..KeyStore::default()
        },
        decrypted_members,
    }
}
