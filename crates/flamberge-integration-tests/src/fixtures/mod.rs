//! Synthesized DRM-encrypted books, one builder per scheme.
//!
//! # Fixture provenance
//!
//! Shipping a real DRM-protected ebook would mean distributing copyrighted,
//! DRMed content, so **no fixture here contains any real book**. Every fixture is
//! constructed at run time from this project's own crypto primitives
//! (`flamberge-crypto`) and public format helpers, wrapping a short synthetic
//! plaintext under a key the test controls. The byte layouts mirror what the
//! corresponding `flamberge-schemes` decryptor already round-trips in its unit
//! tests, so a fixture is faithful to the real container without embedding one.
//!
//! Each submodule documents the `docs/DEDRM_SCHEMES.md` section it mirrors:
//!
//! * [`epub`] — Adobe ADEPT (§7.3) and Barnes & Noble (§4.4) EPUB.
//! * [`pdf`] — ADEPT and B&N `EBX_HANDLER` PDF (§7.4 / §4.4).
//! * [`mobipocket`] — Mobipocket / Kindle PID (§2).
//! * [`topaz`] — Topaz `TPZ0` (§5).
//! * [`kfx`] — KFX-ZIP voucher unwrap + content decrypt (§3).
//! * [`ereader`] — eReader `.pdb` (§8).
//! * [`kobo`] — Kobo KEPUB with an external library DB (§9).

use std::collections::BTreeMap;
use std::io::{Read, Write};

use base64::Engine;
use flamberge_crypto::aes;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPrivateKey};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

pub mod epub;
pub mod ereader;
pub mod kfx;
pub mod kobo;
pub mod mobipocket;
pub mod pdf;
pub mod topaz;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// XML namespace for the Adobe ADEPT `rights.xml` elements.
pub const ADEPT_NS: &str = "http://ns.adobe.com/adept";

/// Append PKCS#7 padding out to a whole `block`.
pub fn pkcs7_pad(data: &[u8], block: usize) -> Vec<u8> {
    let pad = block - data.len() % block;
    let mut out = data.to_vec();
    out.extend(std::iter::repeat_n(pad as u8, pad));
    out
}

/// Raw DEFLATE (zlib `windowBits = -15`) — the inverse of the raw-inflate the
/// EPUB/KFX decryptors apply to a decrypted member.
pub fn raw_deflate(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// Build a ZIP/OCF container from `(name, bytes)` members: `mimetype` is stored,
/// everything else is deflated — the shape the OCF reader parses and repackages.
pub fn build_zip(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut w = ZipWriter::new(std::io::Cursor::new(&mut buf));
        for (name, bytes) in members {
            let method = if *name == "mimetype" {
                CompressionMethod::Stored
            } else {
                CompressionMethod::Deflated
            };
            w.start_file(
                *name,
                SimpleFileOptions::default().compression_method(method),
            )
            .unwrap();
            w.write_all(bytes).unwrap();
        }
        w.finish().unwrap();
    }
    buf
}

/// Read a ZIP back into a `name -> bytes` map, for asserting recovered content.
pub fn read_zip(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    let mut out = BTreeMap::new();
    for i in 0..archive.len() {
        let mut f = archive.by_index(i).unwrap();
        let name = f.name().to_owned();
        let mut b = Vec::new();
        f.read_to_end(&mut b).unwrap();
        out.insert(name, b);
    }
    out
}

/// zlib-wrapped DEFLATE (RFC 1950, with header/checksum) — the inverse of the
/// zlib inflate the PDF content-stream, eReader page, and Topaz page decoders
/// apply. Distinct from [`raw_deflate`] (headerless, `windowBits = -15`).
pub fn zlib(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// A minimal ADEPT `rights.xml` carrying the base64 wrapped book key inside
/// `adept:licenseToken/adept:encryptedKey` (§4.4/§7.3). Shared by the EPUB and
/// EBX_HANDLER-PDF fixtures.
pub fn rights_xml(key_b64: &str) -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\"?>\
         <adept:rights xmlns:adept=\"{ADEPT_NS}\">\
         <adept:licenseToken><adept:encryptedKey>{key_b64}</adept:encryptedKey>\
         </adept:licenseToken></adept:rights>"
    )
    .into_bytes()
}

/// The B&N AES user key: the first 16 bytes of the base64-decoded ccHash (§4.4).
pub fn user_key_from_cchash(cchash: &str) -> [u8; 16] {
    let raw = B64.decode(cchash).unwrap();
    let mut k = [0u8; 16];
    k.copy_from_slice(&raw[..16]);
    k
}

/// B&N book-key wrap: `AES-128-CBC(user_key, zero IV, pkcs7(0xAA*16 || book_key))`
/// — 48 raw ciphertext bytes (§4.4). Callers base64-encode as needed.
pub fn bn_wrap(user_key: &[u8; 16], book_key: &[u8; 16]) -> Vec<u8> {
    let mut plain = vec![0xAAu8; 16];
    plain.extend_from_slice(book_key);
    aes::cbc_encrypt(user_key, &[0u8; 16], &pkcs7_pad(&plain, 16)).unwrap()
}

/// Textbook RSA public op (`m^e mod n`, left-zero-padded to the modulus length)
/// over a PKCS#1 v1.5 encryption block `00 02 <FF padding> 00 <payload>` — the
/// inverse of the ADEPT scheme's private decrypt. Shared by the ADEPT EPUB and
/// PDF fixtures.
pub fn rsa_wrap_pkcs1(key: &RsaPrivateKey, payload: &[u8]) -> Vec<u8> {
    let modn = key.size();
    let mut block = vec![0x00, 0x02];
    block.extend(std::iter::repeat_n(0xFFu8, modn - payload.len() - 3));
    block.push(0x00);
    block.extend_from_slice(payload);

    let c = BigUint::from_bytes_be(&block).modpow(key.e(), key.n());
    let raw = c.to_bytes_be();
    let mut out = vec![0u8; modn - raw.len()];
    out.extend_from_slice(&raw);
    out
}
