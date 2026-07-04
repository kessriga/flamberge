//! Barnes & Noble ("ignoble") DRM removal (EPUB + PDF).
//!
//! EPUB (§4.4): AES-128-CBC unwrap `rights.xml` key with `user_key[:16]`
//! (zero IV) → book key = last 16 bytes → per file AES-CBC, drop first 16 bytes,
//! strip PKCS#7, raw inflate. PDF (§4.5): EBX_HANDLER + RC4 per object.
//! B&N user keys are generated offline via `flamberge_keys::ignoble`.
//! Reference: `docs/DEDRM_SCHEMES.md` §4; `ignobleepub.py`.

use std::collections::BTreeMap;

use flamberge_crypto::{aes, kdf};
use flamberge_formats::ocf::{self, EpubScheme, OcfEncryption};
use flamberge_formats::pdf::PdfDocument;

use crate::epub_common::{decode_b64, decrypt_member};
use crate::{pdf_common, DecryptedBook, KeyStore, Result, SchemeError};

/// Remove Barnes & Noble DRM from an EPUB: AES-unwrap the `rights.xml` book key
/// with a candidate user key, decrypt + inflate each encrypted member, and
/// repackage the OCF.
///
/// Returns [`SchemeError::NotThisScheme`] for non-B&N input (plain zips, DRM-free
/// EPUBs, or ADEPT-shaped containers) so `.epub` dispatch falls through to ADEPT,
/// and [`SchemeError::NoKeyWorked`] when no supplied B&N key unwraps the book key.
pub fn decrypt_epub(input: &[u8], keys: &KeyStore) -> Result<DecryptedBook> {
    // Claim only B&N-shaped OCF containers (64-char wrapped key, §4.4); anything
    // else (ADEPT's 172-char key, or DRM-free) falls through.
    if !input.starts_with(b"PK\x03\x04") || !ocf::is_encrypted_epub(input)? {
        return Err(SchemeError::NotThisScheme);
    }
    let enc = OcfEncryption::parse(input)?;
    if enc.scheme() != Some(EpubScheme::BarnesNoble) {
        return Err(SchemeError::NotThisScheme);
    }
    let wrapped_b64 = enc
        .wrapped_key_b64
        .as_deref()
        .ok_or(SchemeError::NotThisScheme)?;
    let wrapped = decode_b64(wrapped_b64)?;

    let book_key = recover_book_key(&wrapped, keys)?;

    let members = ocf::read_all_members(input)?;
    let mut replacements = BTreeMap::new();
    for (name, data) in &members {
        if enc.encrypted_paths.contains(name) {
            replacements.insert(name.clone(), decrypt_member(&book_key, data)?);
        }
    }

    let data = ocf::repackage(input, &replacements)?;
    Ok(DecryptedBook {
        data,
        extension: "epub".to_string(),
        title: None,
    })
}

/// Try each candidate B&N user key (a 28-char base64 `ccHash`) until one unwraps
/// the book key. A key whose AES block fails PKCS#7 validation is the "wrong key"
/// signal, and the next candidate is tried (§4.4). With no candidates — or none
/// matching — this is [`SchemeError::NoKeyWorked`].
fn recover_book_key(wrapped: &[u8], keys: &KeyStore) -> Result<[u8; 16]> {
    for cchash in &keys.bandn_keys {
        // A ccHash that fails to decode or validate is skipped, like a wrong key.
        if let Ok(Some(key)) = unwrap_book_key(cchash, wrapped) {
            return Ok(key);
        }
    }
    Err(SchemeError::NoKeyWorked)
}

/// AES-unwrap one candidate (§4.4): the user key is the first 16 bytes of the
/// base64-decoded ccHash; AES-128-CBC decrypt the wrapped key with a zero IV,
/// strip PKCS#7, and the book key is the last 16 bytes. `Ok(None)` means a clean
/// decrypt but the wrong key (invalid PKCS#7, or too few bytes to hold a key);
/// `Err` means the ccHash itself was unusable.
fn unwrap_book_key(cchash_b64: &str, wrapped: &[u8]) -> Result<Option<[u8; 16]>> {
    let raw = decode_b64(cchash_b64)?;
    if raw.len() < 16 {
        return Ok(None);
    }
    let user_key = &raw[..16];
    let plain = aes::cbc_decrypt(user_key, &[0u8; 16], wrapped)?;
    // Invalid padding under this key means it is the wrong key (§4.4).
    let unpadded = match kdf::pkcs7_unpad(&plain, 16) {
        Ok(u) => u,
        Err(_) => return Ok(None),
    };
    if unpadded.len() < 16 {
        return Ok(None);
    }
    let mut key = [0u8; 16];
    key.copy_from_slice(&unpadded[unpadded.len() - 16..]);
    Ok(Some(key))
}

/// Remove Barnes & Noble DRM from a PDF (§4.5, `EBX_HANDLER`): recover the book
/// key from the `/Encrypt` `ADEPT_LICENSE` (base64 → inflate → adept XML →
/// zero-IV AES unwrap with the user key), RC4-decipher every object, and re-emit
/// a clean PDF.
///
/// Returns [`SchemeError::NotThisScheme`] for non-PDF input, non-EBX handlers, or
/// an ADEPT-shaped (RSA) license, so `.pdf` dispatch falls through to
/// [`crate::adept::decrypt_pdf`]; and [`SchemeError::NoKeyWorked`] when no
/// supplied B&N key unwraps the book key.
pub fn decrypt_pdf(input: &[u8], keys: &KeyStore) -> Result<DecryptedBook> {
    if !input.starts_with(b"%PDF") {
        return Err(SchemeError::NotThisScheme);
    }
    let doc = PdfDocument::parse(input)?;
    let license = pdf_common::ebx_license(&doc)?;
    // Only the 48-byte (zero-IV AES) wrapped key is B&N's; ADEPT's RSA block
    // falls through to adept::decrypt_pdf.
    if license.wrapped.len() != pdf_common::BN_WRAPPED_LEN {
        return Err(SchemeError::NotThisScheme);
    }
    let book_key = recover_book_key(&license.wrapped, keys)?;
    let data = pdf_common::decrypt_to_clean_pdf(&doc, book_key, license.version)?;
    Ok(DecryptedBook {
        data,
        extension: "pdf".to_string(),
        title: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::{Read, Write};

    use base64::Engine;
    use flamberge_crypto::aes;
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    const ADEPT_NS: &str = "http://ns.adobe.com/adept";
    const ENC_NS: &str = "http://www.w3.org/2001/04/xmlenc#";
    const B64: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::STANDARD;

    // --- helpers mirroring what a real B&N packager does ---

    fn pkcs7_pad(data: &[u8], block: usize) -> Vec<u8> {
        let pad = block - data.len() % block;
        let mut out = data.to_vec();
        out.extend(std::iter::repeat_n(pad as u8, pad));
        out
    }

    fn raw_deflate(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// The first 16 bytes of the base64-decoded 28-char ccHash — the AES user key.
    fn user_key_from_cchash(cchash: &str) -> [u8; 16] {
        let raw = B64.decode(cchash).unwrap();
        let mut k = [0u8; 16];
        k.copy_from_slice(&raw[..16]);
        k
    }

    /// Build the 64-char (48-byte) `rights.xml` wrapped key as B&N stores it:
    /// AES-128-CBC(user_key, zero IV, pkcs7(prefix ‖ book_key)) where the book key
    /// is the last 16 bytes of the unpadded plaintext (§4.4).
    fn wrap_book_key(user_key: &[u8; 16], book_key: &[u8; 16]) -> String {
        let mut plain = vec![0xAAu8; 16];
        plain.extend_from_slice(book_key);
        let wrapped = aes::cbc_encrypt(user_key, &[0u8; 16], &pkcs7_pad(&plain, 16)).unwrap();
        let b64 = B64.encode(&wrapped);
        assert_eq!(b64.len(), ocf::BN_KEY_LEN, "wrapped key must be 64 chars");
        b64
    }

    /// Encrypt one member as B&N/ADEPT store it: `IV || AES-CBC(book_key, IV,
    /// pkcs7(body))`, where `body` is raw-deflated when `deflate` is set.
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

    fn rights_xml(key_b64: &str) -> Vec<u8> {
        format!(
            "<?xml version=\"1.0\"?>\
             <adept:rights xmlns:adept=\"{ADEPT_NS}\">\
             <adept:licenseToken><adept:encryptedKey>{key_b64}</adept:encryptedKey>\
             </adept:licenseToken></adept:rights>"
        )
        .into_bytes()
    }

    fn encryption_xml(paths: &[&str]) -> Vec<u8> {
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

    fn build_zip(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
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

    /// A B&N EPUB whose user key is derived from `flamberge_keys::ignoble`
    /// (AC#4), wrapping `content_key`, with one deflated and one stored member.
    /// Returns `(cchash, epub_bytes, chapter_plaintext, css_plaintext)`.
    fn synth_bn_epub(content_key: [u8; 16]) -> (String, Vec<u8>, Vec<u8>, Vec<u8>) {
        let cchash = flamberge_keys::ignoble::generate_key("Ada Lovelace", "4111 1111 1111 1111")
            .expect("keygen");
        let user_key = user_key_from_cchash(&cchash);
        let wrapped_b64 = wrap_book_key(&user_key, &content_key);

        let chapter = b"<html><body>Chapter one, now readable.</body></html>".to_vec();
        let css = b"body { color: black; }".to_vec();

        let epub = build_zip(&[
            ("mimetype", b"application/epub+zip".to_vec()),
            (ocf::RIGHTS_XML, rights_xml(&wrapped_b64)),
            (
                ocf::ENCRYPTION_XML,
                encryption_xml(&["OEBPS/ch1.html", "OEBPS/style.css"]),
            ),
            (
                "OEBPS/ch1.html",
                encrypt_member(&content_key, &chapter, true),
            ),
            ("OEBPS/style.css", encrypt_member(&content_key, &css, false)),
            ("OEBPS/content.opf", b"<package/>".to_vec()),
        ]);
        (cchash, epub, chapter, css)
    }

    fn read_zip(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
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

    // --- unit tests ---

    #[test]
    fn unwrap_book_key_recovers_last_16_bytes() {
        let cchash =
            flamberge_keys::ignoble::generate_key("Grace Hopper", "5500005555555559").unwrap();
        let user_key = user_key_from_cchash(&cchash);
        let book_key = [0x42u8; 16];
        let wrapped = decode_b64(&wrap_book_key(&user_key, &book_key)).unwrap();

        assert_eq!(unwrap_book_key(&cchash, &wrapped).unwrap(), Some(book_key));
    }

    #[test]
    fn unwrap_book_key_wrong_key_is_none_not_error() {
        // Wrapping under user key A, unwrapping with ccHash B yields a plaintext
        // whose PKCS#7 padding is (almost surely) invalid => wrong-key signal.
        let cchash_a =
            flamberge_keys::ignoble::generate_key("Alan Turing", "4000000000000002").unwrap();
        let cchash_b =
            flamberge_keys::ignoble::generate_key("Alan Turing", "4000000000000010").unwrap();
        let wrapped = decode_b64(&wrap_book_key(
            &user_key_from_cchash(&cchash_a),
            &[0x11u8; 16],
        ))
        .unwrap();

        assert_eq!(unwrap_book_key(&cchash_b, &wrapped).unwrap(), None);
    }

    // --- end-to-end (AC#4), through top-level `.epub` dispatch ---

    #[test]
    fn decrypt_epub_end_to_end_via_dispatch() {
        let content_key = [0x9Cu8; 16];
        let (cchash, epub, chapter, css) = synth_bn_epub(content_key);

        let keys = KeyStore {
            bandn_keys: vec![cchash],
            ..KeyStore::default()
        };

        // `.epub` dispatch tries IgnobleEpub first; it must claim the B&N book.
        let book = crate::decrypt(&epub, "epub", &keys).unwrap();
        assert_eq!(book.extension, "epub");

        let out = read_zip(&book.data);
        assert_eq!(out["OEBPS/ch1.html"], chapter);
        assert_eq!(out["OEBPS/style.css"], css);
        assert_eq!(out["OEBPS/content.opf"], b"<package/>");
        // DRM META files are dropped by the repackager.
        assert!(!out.contains_key(ocf::RIGHTS_XML));
        assert!(!out.contains_key(ocf::ENCRYPTION_XML));
        assert_eq!(out["mimetype"], b"application/epub+zip");
    }

    #[test]
    fn wrong_key_reports_no_key_worked() {
        let (_cc, epub, _c, _s) = synth_bn_epub([0x01u8; 16]);
        let other =
            flamberge_keys::ignoble::generate_key("Somebody Else", "6011000000000004").unwrap();
        let keys = KeyStore {
            bandn_keys: vec![other],
            ..KeyStore::default()
        };
        assert!(matches!(
            decrypt_epub(&epub, &keys),
            Err(SchemeError::NoKeyWorked)
        ));
    }

    #[test]
    fn no_keys_reports_no_key_worked() {
        let (_cc, epub, _c, _s) = synth_bn_epub([0x02u8; 16]);
        assert!(matches!(
            decrypt_epub(&epub, &KeyStore::default()),
            Err(SchemeError::NoKeyWorked)
        ));
    }

    #[test]
    fn adept_shaped_epub_falls_through() {
        // A 172-char (ADEPT) wrapped key must not be claimed by B&N.
        let epub = build_zip(&[
            ("mimetype", b"application/epub+zip".to_vec()),
            (ocf::RIGHTS_XML, rights_xml(&"A".repeat(ocf::ADEPT_KEY_LEN))),
            (ocf::ENCRYPTION_XML, encryption_xml(&["a.html"])),
            ("a.html", vec![0u8; 32]),
        ]);
        assert!(matches!(
            decrypt_epub(&epub, &KeyStore::default()),
            Err(SchemeError::NotThisScheme)
        ));
    }

    #[test]
    fn plain_zip_is_not_this_scheme() {
        let zip = build_zip(&[("mimetype", b"application/epub+zip".to_vec())]);
        assert!(matches!(
            decrypt_epub(&zip, &KeyStore::default()),
            Err(SchemeError::NotThisScheme)
        ));
    }

    #[test]
    fn non_zip_is_not_this_scheme() {
        assert!(matches!(
            decrypt_epub(b"not a zip at all", &KeyStore::default()),
            Err(SchemeError::NotThisScheme)
        ));
    }
}
