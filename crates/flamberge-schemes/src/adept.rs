//! Adobe ADEPT DRM removal (EPUB + PDF).
//!
//! EPUB (§7.3): RSA-unwrap the `rights.xml` book key → AES-128-CBC per file
//! (IV = first 16 ciphertext bytes) → strip PKCS#7 → raw inflate. PDF (§7.4):
//! unwrap `ADEPT_LICENSE` (EBX_HANDLER) → RC4 per object with an MD5-derived key.
//! Reference: `docs/DEDRM_SCHEMES.md` §7; `adobekey.py` (key form), `ineptepub.py`.

use std::collections::BTreeMap;

use flamberge_crypto::rsa;
use flamberge_formats::ocf::{self, EpubScheme, OcfEncryption};
use flamberge_formats::pdf::PdfDocument;

use crate::epub_common::{decode_b64, decrypt_member};
use crate::{pdf_common, DecryptedBook, KeyStore, Result, SchemeError};

/// Remove Adobe ADEPT DRM from an EPUB: RSA-unwrap the book key with a candidate
/// user key, AES-decrypt + inflate each encrypted member, and repackage the OCF.
///
/// Returns [`SchemeError::NotThisScheme`] for non-ADEPT input (plain zips,
/// DRM-free EPUBs, or B&N-shaped containers) so dispatch falls through, and
/// [`SchemeError::NoKeyWorked`] when no supplied ADEPT key unwraps the book key.
pub fn decrypt_epub(input: &[u8], keys: &KeyStore) -> Result<DecryptedBook> {
    // Only claim actual ZIP/OCF containers that carry the ADEPT META markers.
    if !input.starts_with(b"PK\x03\x04") || !ocf::is_encrypted_epub(input)? {
        return Err(SchemeError::NotThisScheme);
    }

    let enc = OcfEncryption::parse(input)?;
    // The 172-char wrapped-key length is the offline ADEPT/B&N discriminator
    // (§7.3); anything else (B&N, or DRM-free) is not ours.
    if enc.scheme() != Some(EpubScheme::Adept) {
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

/// Remove Adobe ADEPT DRM from a PDF (§7.4, `EBX_HANDLER`): recover the book key
/// from the `/Encrypt` `ADEPT_LICENSE` (base64 → inflate → adept XML →
/// RSA-unwrap), RC4-decipher every object, and re-emit a clean PDF.
///
/// Returns [`SchemeError::NotThisScheme`] for non-PDF input, non-EBX handlers, or
/// a B&N-shaped (48-byte AES) license — the last so `.pdf` dispatch falls through
/// to [`crate::ignoble::decrypt_pdf`] — and [`SchemeError::NoKeyWorked`] when no
/// supplied ADEPT key unwraps the book key.
pub fn decrypt_pdf(input: &[u8], keys: &KeyStore) -> Result<DecryptedBook> {
    if !input.starts_with(b"%PDF") {
        return Err(SchemeError::NotThisScheme);
    }
    let doc = PdfDocument::parse(input)?;
    let license = pdf_common::ebx_license(&doc)?;
    // A 48-byte (zero-IV AES) wrapped key is B&N's, not ADEPT's RSA block.
    if license.wrapped.len() == pdf_common::BN_WRAPPED_LEN {
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

/// Try each candidate ADEPT user key (a PKCS#1 RSA DER) until one unwraps the
/// book key. A key whose RSA block fails the `[-17]==0x00` separator check is the
/// "wrong key" signal, and the next candidate is tried (§7.3). With no candidate
/// keys — or none matching — this is [`SchemeError::NoKeyWorked`].
fn recover_book_key(wrapped: &[u8], keys: &KeyStore) -> Result<[u8; 16]> {
    for der in &keys.adept_keys {
        // A DER that fails to parse or decrypt is skipped, like a wrong key.
        if let Ok(Some(key)) = unwrap_book_key(der, wrapped) {
            return Ok(key);
        }
    }
    Err(SchemeError::NoKeyWorked)
}

/// RSA-unwrap one candidate: raw-decrypt, then apply the ADEPT separator rule
/// (§7.1/§7.3). `Ok(None)` means a clean decrypt but the wrong key (the `[-17]`
/// separator is absent); `Err` means the DER itself was unusable.
fn unwrap_book_key(der: &[u8], wrapped: &[u8]) -> Result<Option<[u8; 16]>> {
    let block = rsa::private_decrypt_raw(der, wrapped)?;
    // Need the separator byte at index -17 plus 16 key bytes (§7.3).
    if block.len() <= 16 || block[block.len() - 17] != 0x00 {
        return Ok(None);
    }
    let mut key = [0u8; 16];
    key.copy_from_slice(&block[block.len() - 16..]);
    Ok(Some(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epub_common::test_support::*;

    use ::rsa::pkcs1::EncodeRsaPrivateKey;
    use ::rsa::traits::PublicKeyParts;
    use ::rsa::{BigUint, RsaPrivateKey};
    use base64::Engine;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    /// A reproducible RSA key source. Seeding per call site keeps keygen — and so
    /// the wrong-key `[-17]` separator check — deterministic rather than ~1/256
    /// flaky, while distinct seeds still yield genuinely independent keys.
    fn seeded_rng(seed: u64) -> StdRng {
        StdRng::seed_from_u64(seed)
    }

    // --- ADEPT-specific crypto helpers (shared EPUB builders live in
    // `epub_common::test_support`) ---

    /// Textbook RSA public op (`m^e mod n`) to wrap a block, inverse of the
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

    /// A fresh 1024-bit key plus a synthetic ADEPT EPUB wrapping `content_key`,
    /// with one deflated and one stored encrypted member. Returns
    /// `(der, epub_bytes, chapter_plaintext, css_plaintext)`.
    fn synth_adept_epub(content_key: [u8; 16]) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut rng = seeded_rng(1);
        let key = RsaPrivateKey::new(&mut rng, 1024).expect("keygen");
        let der = key.to_pkcs1_der().unwrap().as_bytes().to_vec();

        let wrapped = rsa_wrap(&key, &pkcs1_block(key.size(), &content_key));
        let wrapped_b64 = base64::engine::general_purpose::STANDARD.encode(&wrapped);
        assert_eq!(
            wrapped_b64.len(),
            ocf::ADEPT_KEY_LEN,
            "wrapped key must be 172 chars"
        );

        let chapter = b"<html><body>Chapter one, now readable.</body></html>".to_vec();
        let css = b"body { color: black; }".to_vec();

        let epub = build_zip(&[
            ("mimetype", b"application/epub+zip".to_vec()),
            (ocf::RIGHTS_XML, rights_xml(&wrapped_b64)),
            (
                ocf::ENCRYPTION_XML,
                encryption_xml(&["OEBPS/ch1.html", "OEBPS/style.css"]),
            ),
            // Deflated then encrypted (the common case).
            (
                "OEBPS/ch1.html",
                encrypt_member(&content_key, &chapter, true),
            ),
            // Stored (not deflated) then encrypted — exercises inflate pass-through.
            ("OEBPS/style.css", encrypt_member(&content_key, &css, false)),
            // An unencrypted member copied verbatim.
            ("OEBPS/content.opf", b"<package/>".to_vec()),
        ]);
        (der, epub, chapter, css)
    }

    // --- unit tests ---

    #[test]
    fn unwrap_book_key_applies_minus17_rule() {
        let mut rng = seeded_rng(2);
        let key = RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let der = key.to_pkcs1_der().unwrap().as_bytes().to_vec();
        let content_key = [0x42u8; 16];
        let wrapped = rsa_wrap(&key, &pkcs1_block(key.size(), &content_key));

        assert_eq!(unwrap_book_key(&der, &wrapped).unwrap(), Some(content_key));
    }

    #[test]
    fn unwrap_book_key_wrong_key_is_none_not_error() {
        // Two independent keys: wrapping with A, unwrapping with B yields a block
        // whose [-17] byte is (almost surely) not 0x00 => wrong-key signal.
        let mut rng = seeded_rng(3);
        let key_a = RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let key_b = RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let der_b = key_b.to_pkcs1_der().unwrap().as_bytes().to_vec();
        let wrapped = rsa_wrap(&key_a, &pkcs1_block(key_a.size(), &[0x11u8; 16]));

        assert_eq!(unwrap_book_key(&der_b, &wrapped).unwrap(), None);
    }

    #[test]
    fn decrypt_member_handles_deflated_and_stored() {
        let key = [0x7Fu8; 16];
        let text = b"the quick brown fox jumps over the lazy dog".to_vec();

        let deflated = encrypt_member(&key, &text, true);
        assert_eq!(decrypt_member(&key, &deflated).unwrap(), text);

        let stored = encrypt_member(&key, &text, false);
        assert_eq!(decrypt_member(&key, &stored).unwrap(), text);
    }

    #[test]
    fn decrypt_member_rejects_misaligned_input() {
        assert!(decrypt_member(&[0u8; 16], b"not-block-aligned").is_err());
    }

    // --- end-to-end (acceptance criterion #5), through top-level dispatch ---

    #[test]
    fn decrypt_epub_end_to_end_via_dispatch() {
        let content_key = [0x9Cu8; 16];
        let (der, epub, chapter, css) = synth_adept_epub(content_key);

        let keys = KeyStore {
            adept_keys: vec![der],
            ..KeyStore::default()
        };

        // Goes through `.epub` dispatch: IgnobleEpub must fall through to ADEPT.
        let book = crate::decrypt(&epub, "epub", &keys).unwrap();
        assert_eq!(book.extension, "epub");

        let out = read_zip(&book.data);
        assert_eq!(out["OEBPS/ch1.html"], chapter);
        assert_eq!(out["OEBPS/style.css"], css);
        assert_eq!(out["OEBPS/content.opf"], b"<package/>");
        // DRM META files are dropped by the repackager.
        assert!(!out.contains_key(ocf::RIGHTS_XML));
        assert!(!out.contains_key(ocf::ENCRYPTION_XML));
        // mimetype survives.
        assert_eq!(out["mimetype"], b"application/epub+zip");
    }

    /// AC #4: a key recovered from a fixture `activation.dat` (via the real
    /// `flamberge_keys::adobe` extractor) populates `adept_keys` and decrypts an
    /// ADEPT EPUB end to end.
    #[test]
    fn decrypt_epub_via_extracted_activation_dat_key() {
        let content_key = [0x3Au8; 16];
        let (der, epub, chapter, css) = synth_adept_epub(content_key);

        // Wrap the DER as ADE stores it on macOS: 26-byte header ‖ DER, base64.
        let mut blob = vec![0u8; flamberge_keys::adobe::HEADER_STRIP_LEN];
        blob.extend_from_slice(&der);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
        let activation_dat = format!(
            "<activationInfo xmlns:adept=\"{ADEPT_NS}\"><adept:credentials>\
             <adept:privateLicenseKey>{b64}</adept:privateLicenseKey>\
             </adept:credentials></activationInfo>"
        );

        let extracted = flamberge_keys::adobe::parse_activation_dat(&activation_dat).unwrap();
        assert_eq!(extracted, vec![der]);

        let keys = KeyStore {
            adept_keys: extracted,
            ..KeyStore::default()
        };
        let book = crate::decrypt(&epub, "epub", &keys).unwrap();
        let out = read_zip(&book.data);
        assert_eq!(out["OEBPS/ch1.html"], chapter);
        assert_eq!(out["OEBPS/style.css"], css);
    }

    #[test]
    fn wrong_key_reports_no_key_worked() {
        let (_der, epub, _c, _s) = synth_adept_epub([0x01u8; 16]);
        let mut rng = seeded_rng(4);
        let other = RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let keys = KeyStore {
            adept_keys: vec![other.to_pkcs1_der().unwrap().as_bytes().to_vec()],
            ..KeyStore::default()
        };
        assert!(matches!(
            decrypt_epub(&epub, &keys),
            Err(SchemeError::NoKeyWorked)
        ));
    }

    #[test]
    fn no_keys_reports_no_key_worked() {
        let (_der, epub, _c, _s) = synth_adept_epub([0x02u8; 16]);
        assert!(matches!(
            decrypt_epub(&epub, &KeyStore::default()),
            Err(SchemeError::NoKeyWorked)
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

    #[test]
    fn barnes_noble_shaped_epub_falls_through() {
        // A 64-char (B&N) wrapped key must not be claimed by ADEPT.
        let epub = build_zip(&[
            ("mimetype", b"application/epub+zip".to_vec()),
            (ocf::RIGHTS_XML, rights_xml(&"B".repeat(ocf::BN_KEY_LEN))),
            (ocf::ENCRYPTION_XML, encryption_xml(&["a.html"])),
            ("a.html", vec![0u8; 32]),
        ]);
        assert!(matches!(
            decrypt_epub(&epub, &KeyStore::default()),
            Err(SchemeError::NotThisScheme)
        ));
    }
}
