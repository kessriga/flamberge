//! Shared EBX_HANDLER PDF decryption used by both the Adobe ADEPT (§7.4) and
//! Barnes & Noble (§4.5) schemes. The two differ only in how the book key is
//! unwrapped (RSA vs zero-IV AES); the `/Encrypt` license extraction, the
//! per-object RC4 key derivation, and the clean re-serialization are identical.
//!
//! A faithful port of `ineptpdf.initialize_ebx` / `genkey_v2` / `genkey_v3` /
//! `decrypt_rc4` and `PDFSerializer`. The AES content branch (`Adobe.APS` /
//! Standard V4, `genkey_v4`) and the German Onleihe principal-key path are out
//! of scope — EBX_HANDLER retail books use RC4.
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §7.4 / §4.5; `ineptpdf.py`, `ignoblepdf.py`.

use flamberge_crypto::{digest, rc4};
use flamberge_formats::pdf::{Object, PdfDocument, PdfSerializer, FILTER_EBX_HANDLER};

use crate::epub_common::{decode_b64, invalid, raw_inflate};
use crate::{Result, SchemeError};

/// The wrapped-key byte length that marks a **B&N**-wrapped EBX license: a
/// three-block zero-IV AES-CBC ciphertext. ADEPT instead wraps with RSA, giving
/// the modulus size (≥128 bytes). This mirrors the 64-vs-172-char OCF
/// discriminator used for the EPUB schemes (`ocf::EpubScheme`).
pub(crate) const BN_WRAPPED_LEN: usize = 48;

/// The still-wrapped book key pulled from a PDF's EBX_HANDLER `/Encrypt` dict,
/// plus the per-object key-derivation version (2 or 3) selected by `/V`.
pub(crate) struct EbxLicense {
    /// The base64-decoded `encryptedKey`: an RSA block (ADEPT) or a zero-IV
    /// AES-CBC ciphertext (B&N). Unwrapped to the 16-byte book key by the caller.
    pub wrapped: Vec<u8>,
    /// `genkey` version: 3 when the `/Encrypt` `/V` is 3, else 2.
    pub version: u8,
}

/// Read the EBX_HANDLER license out of a PDF's `/Encrypt` dictionary.
///
/// Resolves `/Encrypt`, requires `/Filter == EBX_HANDLER` (otherwise
/// [`SchemeError::NotThisScheme`], so the non-EBX handlers fall through), then
/// pulls `ADEPT_LICENSE`: base64 → raw inflate (−15) → adept XML →
/// `encryptedKey` → base64-decoded wrapped key.
pub(crate) fn ebx_license(doc: &PdfDocument) -> Result<EbxLicense> {
    let encrypt = doc.encrypt().ok_or(SchemeError::NotThisScheme)?;
    let encrypt = doc.resolve(encrypt)?;
    let dict = encrypt.as_dict().ok_or(SchemeError::NotThisScheme)?;

    // Only the EBX_HANDLER filter is ours; `Standard`/`Adobe.APS` are not.
    if dict.get("Filter").and_then(Object::as_name) != Some(FILTER_EBX_HANDLER) {
        return Err(SchemeError::NotThisScheme);
    }

    let license = dict
        .get("ADEPT_LICENSE")
        .and_then(Object::as_str_bytes)
        .ok_or_else(|| invalid("EBX_HANDLER /Encrypt has no ADEPT_LICENSE"))?;
    let license_b64 = std::str::from_utf8(license)
        .map_err(|_| invalid("ADEPT_LICENSE is not valid base64 text"))?;
    let compressed = decode_b64(license_b64)?;
    let xml = raw_inflate(&compressed).ok_or_else(|| invalid("ADEPT_LICENSE inflate failed"))?;
    let key_b64 = extract_encrypted_key(&xml)?;
    let wrapped = decode_b64(&key_b64)?;

    let version = match doc
        .resolve(dict.get("V").unwrap_or(&Object::Null))
        .ok()
        .as_ref()
        .and_then(Object::as_int)
    {
        Some(3) => 3,
        _ => 2,
    };
    Ok(EbxLicense { wrapped, version })
}

/// Extract the `encryptedKey` element's text from the (namespaced) adept rights
/// XML — the equivalent of `etree.findtext('.//{adept}encryptedKey')`.
///
/// The document is small and well-formed, so this scans for the first element
/// whose *local* name is `encryptedKey` (matching `<encryptedKey>` and
/// `<adept:encryptedKey>`) and returns its text up to the closing tag.
fn extract_encrypted_key(xml: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(xml).map_err(|_| invalid("adept rights XML is not UTF-8"))?;
    let mut search = text;
    while let Some(rel) = search.find("encryptedKey") {
        let after = &search[rel + "encryptedKey".len()..];
        // The name must end here: the next char closes the tag or is whitespace,
        // so we don't match a longer name like `encryptedKeyInfo`.
        let boundary = after.chars().next();
        if matches!(boundary, Some('>' | ' ' | '\t' | '\r' | '\n' | '/')) {
            if let Some(gt) = after.find('>') {
                let body = &after[gt + 1..];
                if let Some(lt) = body.find('<') {
                    return Ok(body[..lt].trim().to_string());
                }
            }
        }
        search = after;
    }
    Err(invalid("adept rights XML has no encryptedKey"))
}

/// Decrypt every object with the recovered book key and re-emit a clean PDF.
///
/// Installs an RC4 per-object [`Decipher`](flamberge_formats::pdf::Decipher) on
/// `doc` (`genkey_v2`/`v3` per §7.4/§4.5), then serializes: generation numbers
/// forced to 0, `/Encrypt` dropped, object streams dissolved.
pub(crate) fn decrypt_to_clean_pdf(
    doc: &PdfDocument,
    book_key: [u8; 16],
    version: u8,
) -> Result<Vec<u8>> {
    doc.set_decipher(Box::new(move |objid, genno, data| {
        let key = genkey(version, &book_key, objid, genno);
        rc4::apply(&key, data)
    }));
    Ok(PdfSerializer::new(doc).serialize()?)
}

/// Derive the per-object RC4 key for the selected `genkey` version.
fn genkey(version: u8, book_key: &[u8; 16], objid: u32, genno: u16) -> Vec<u8> {
    match version {
        3 => genkey_v3(book_key, objid, genno),
        _ => genkey_v2(book_key, objid, genno),
    }
}

/// `genkey_v2` (§7.4): `MD5(book_key ‖ objid_LE[:3] ‖ genno_LE[:2])`, truncated
/// to `min(len(book_key) + 5, 16)` bytes.
fn genkey_v2(book_key: &[u8; 16], objid: u32, genno: u16) -> Vec<u8> {
    let mut key = book_key.to_vec();
    key.extend_from_slice(&objid.to_le_bytes()[..3]);
    key.extend_from_slice(&genno.to_le_bytes()[..2]);
    truncate_hash(&digest::md5(&key), book_key.len())
}

/// `genkey_v3` (§7.4): `objid ^= 0x3569ac`, `genno ^= 0xca96`, interleave
/// `objid[0] genno[0] objid[1] genno[1] objid[2]`, append `b"sAlT"`, then the
/// same MD5 + truncation as [`genkey_v2`].
fn genkey_v3(book_key: &[u8; 16], objid: u32, genno: u16) -> Vec<u8> {
    let o = (objid ^ 0x0035_69ac).to_le_bytes();
    let g = ((genno as u32) ^ 0x0000_ca96).to_le_bytes();
    let mut key = book_key.to_vec();
    key.extend_from_slice(&[o[0], g[0], o[1], g[1], o[2]]);
    key.extend_from_slice(b"sAlT");
    truncate_hash(&digest::md5(&key), book_key.len())
}

/// The `[:min(len(book_key) + 5, 16)]` truncation shared by every genkey.
fn truncate_hash(hash: &[u8; 16], key_len: usize) -> Vec<u8> {
    hash[..(key_len + 5).min(16)].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference vectors computed from the Python `genkey_v2`/`genkey_v3` for a
    // fixed book key, guarding the byte layout (LE packing, interleave, salt).
    const BOOK_KEY: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    fn md5_of(parts: &[&[u8]]) -> Vec<u8> {
        let mut buf = Vec::new();
        for p in parts {
            buf.extend_from_slice(p);
        }
        digest::md5(&buf).to_vec()
    }

    #[test]
    fn genkey_v2_matches_reference_layout() {
        let (objid, genno) = (7u32, 3u16);
        // book_key ‖ objid_LE[:3] ‖ genno_LE[:2], full 16-byte MD5 (16+5 -> 16).
        let expected = md5_of(&[
            &BOOK_KEY,
            &objid.to_le_bytes()[..3],
            &genno.to_le_bytes()[..2],
        ]);
        assert_eq!(genkey_v2(&BOOK_KEY, objid, genno), expected);
        assert_eq!(genkey_v2(&BOOK_KEY, objid, genno).len(), 16);
    }

    #[test]
    fn genkey_v3_matches_reference_layout() {
        let (objid, genno) = (42u32, 0u16);
        let o = (objid ^ 0x0035_69ac).to_le_bytes();
        let g = ((genno as u32) ^ 0x0000_ca96).to_le_bytes();
        let expected = md5_of(&[&BOOK_KEY, &[o[0], g[0], o[1], g[1], o[2]], b"sAlT"]);
        assert_eq!(genkey_v3(&BOOK_KEY, objid, genno), expected);
    }

    #[test]
    fn genkey_versions_differ() {
        assert_ne!(
            genkey_v2(&BOOK_KEY, 5, 0),
            genkey_v3(&BOOK_KEY, 5, 0),
            "v2 and v3 must not collide for the same object"
        );
    }

    #[test]
    fn extract_encrypted_key_handles_namespace_and_whitespace() {
        let xml = b"<adept:rights xmlns:adept=\"http://ns.adobe.com/adept\">\
                    <adept:licenseToken><adept:encryptedKey>\n  AAAABBBB==  \n\
                    </adept:encryptedKey></adept:licenseToken></adept:rights>";
        assert_eq!(extract_encrypted_key(xml).unwrap(), "AAAABBBB==");
    }

    #[test]
    fn extract_encrypted_key_ignores_longer_tag_names() {
        // A decoy `encryptedKeyInfo` element must not be matched.
        let xml = b"<r><encryptedKeyInfo>DECOY</encryptedKeyInfo>\
                    <encryptedKey>REAL</encryptedKey></r>";
        assert_eq!(extract_encrypted_key(xml).unwrap(), "REAL");
    }

    #[test]
    fn extract_encrypted_key_absent_is_error() {
        assert!(extract_encrypted_key(b"<r><other>x</other></r>").is_err());
    }

    // ── end-to-end EBX_HANDLER decryption (AC#1–#5) ──────────────────────────

    use std::io::Write;

    use ::rsa::pkcs1::EncodeRsaPrivateKey;
    use ::rsa::traits::PublicKeyParts;
    use ::rsa::{BigUint, RsaPrivateKey};
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use flamberge_crypto::aes;
    use flamberge_formats::pdf::PdfDocument;

    use crate::KeyStore;

    const ADEPT_NS: &str = "http://ns.adobe.com/adept";

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn raw_deflate(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// RC4-encipher `data` for object `objid` — the inverse of what the scheme's
    /// installed decipher does (RC4 is symmetric).
    fn rc4_obj(book_key: &[u8; 16], version: u8, objid: u32, genno: u16, data: &[u8]) -> Vec<u8> {
        rc4::apply(&genkey(version, book_key, objid, genno), data)
    }

    fn rights_xml(encrypted_key_b64: &str) -> Vec<u8> {
        format!(
            "<?xml version=\"1.0\"?>\
             <adept:rights xmlns:adept=\"{ADEPT_NS}\">\
             <adept:licenseToken><adept:encryptedKey>{encrypted_key_b64}</adept:encryptedKey>\
             </adept:licenseToken></adept:rights>"
        )
        .into_bytes()
    }

    /// Base64 of `deflate(-15, rights_xml(base64(wrapped)))` — the `ADEPT_LICENSE`
    /// string value as an EBX_HANDLER `/Encrypt` dict stores it.
    fn adept_license_value(wrapped: &[u8]) -> String {
        let xml = rights_xml(&STANDARD.encode(wrapped));
        STANDARD.encode(raw_deflate(&xml))
    }

    fn pkcs7_pad(data: &[u8], block: usize) -> Vec<u8> {
        let pad = block - data.len() % block;
        let mut out = data.to_vec();
        out.extend(std::iter::repeat_n(pad as u8, pad));
        out
    }

    /// Textbook RSA public op wrapping a PKCS#1 block whose trailing 16 bytes are
    /// `book_key` (with the `\x00` separator at `[-17]`), mirroring `adept.rs`.
    fn adept_wrap(key: &RsaPrivateKey, book_key: &[u8; 16]) -> Vec<u8> {
        let modn = key.size();
        let mut block = vec![0x00, 0x02];
        block.extend(std::iter::repeat_n(0xFFu8, modn - book_key.len() - 3));
        block.push(0x00);
        block.extend_from_slice(book_key);
        let c = BigUint::from_bytes_be(&block).modpow(key.e(), key.n());
        let raw = c.to_bytes_be();
        let mut out = vec![0u8; modn - raw.len()];
        out.extend_from_slice(&raw);
        out
    }

    /// B&N zero-IV AES wrap of `pad16 ‖ book_key`, keyed by the ccHash's first 16
    /// bytes (mirrors `ignoble.rs`). Yields a 48-byte ciphertext.
    fn bn_wrap(user_key: &[u8; 16], book_key: &[u8; 16]) -> Vec<u8> {
        let mut plain = vec![0xAAu8; 16];
        plain.extend_from_slice(book_key);
        aes::cbc_encrypt(user_key, &[0u8; 16], &pkcs7_pad(&plain, 16)).unwrap()
    }

    /// Build a classic-xref EBX_HANDLER PDF: a Flate content stream (obj 4) and a
    /// literal string (obj 5), both RC4-enciphered per object, plus an indirect
    /// `/Encrypt` (obj 6) carrying `license_b64`. `v_field` is the dict's `/V`.
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

        // obj 4: RC4(Flate(page_text)) content stream.
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

        // obj 5: RC4(secret) as a hex string (avoids escaping arbitrary bytes).
        let enc5 = rc4_obj(book_key, version, 5, 0, secret);
        off[5] = buf.len();
        buf.extend_from_slice(format!("5 0 obj\n<{}>\nendobj\n", hex(&enc5)).as_bytes());

        // obj 6: the EBX_HANDLER /Encrypt dict (base64 is literal-string safe).
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

    /// Re-parse a decrypted PDF and pull back (obj4 inflated content, obj5 string).
    fn read_back(pdf: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let doc = PdfDocument::parse(pdf).unwrap();
        assert!(doc.encrypt().is_none(), "/Encrypt must be stripped");
        let content = doc.get_object(4).unwrap();
        let text = content.as_stream().unwrap().decoded().unwrap();
        let secret = doc.get_object(5).unwrap().as_str_bytes().unwrap().to_vec();
        (text, secret)
    }

    fn adept_keys(book_key: &[u8; 16]) -> (Vec<u8>, String) {
        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new(&mut rng, 1024).expect("keygen");
        let der = key.to_pkcs1_der().unwrap().as_bytes().to_vec();
        let license = adept_license_value(&adept_wrap(&key, book_key));
        (der, license)
    }

    fn bn_keys(book_key: &[u8; 16]) -> (String, String) {
        let cchash =
            flamberge_keys::ignoble::generate_key("Ada Lovelace", "4111 1111 1111 1111").unwrap();
        let raw = STANDARD.decode(&cchash).unwrap();
        let mut user_key = [0u8; 16];
        user_key.copy_from_slice(&raw[..16]);
        let license = adept_license_value(&bn_wrap(&user_key, book_key));
        (cchash, license)
    }

    #[test]
    fn adept_pdf_end_to_end_via_dispatch() {
        let book_key = [0x9Cu8; 16];
        let (der, license) = adept_keys(&book_key);
        let page = b"BT /F1 12 Tf (Chapter one, now readable.) Tj ET";
        let secret = b"Secret /Info string, decrypted.";
        // /V 4 is the retail EBX value and must select genkey_v2.
        let pdf = build_ebx_pdf(&book_key, 2, 4, &license, page, secret);

        let keys = KeyStore {
            adept_keys: vec![der],
            ..KeyStore::default()
        };
        let book = crate::decrypt(&pdf, "pdf", &keys).unwrap();
        assert_eq!(book.extension, "pdf");
        assert_eq!(read_back(&book.data), (page.to_vec(), secret.to_vec()));
    }

    #[test]
    fn adept_pdf_genkey_v3_end_to_end() {
        let book_key = [0x3Bu8; 16];
        let (der, license) = adept_keys(&book_key);
        let page = b"genkey_v3 content stream";
        let secret = b"genkey_v3 string";
        let pdf = build_ebx_pdf(&book_key, 3, 3, &license, page, secret);

        let keys = KeyStore {
            adept_keys: vec![der],
            ..KeyStore::default()
        };
        let book = crate::decrypt(&pdf, "pdf", &keys).unwrap();
        assert_eq!(read_back(&book.data), (page.to_vec(), secret.to_vec()));
    }

    #[test]
    fn barnes_noble_pdf_end_to_end_via_dispatch() {
        let book_key = [0x77u8; 16];
        let (cchash, license) = bn_keys(&book_key);
        let page = b"B&N page content";
        let secret = b"B&N secret";
        let pdf = build_ebx_pdf(&book_key, 2, 4, &license, page, secret);

        let keys = KeyStore {
            bandn_keys: vec![cchash],
            ..KeyStore::default()
        };
        // IgnoblePdf is tried first and must claim the 48-byte-wrapped license.
        let book = crate::decrypt(&pdf, "pdf", &keys).unwrap();
        assert_eq!(read_back(&book.data), (page.to_vec(), secret.to_vec()));
    }

    #[test]
    fn adept_pdf_no_working_key_reports_no_key_worked() {
        // A well-formed EBX_HANDLER PDF with no candidate key must surface a
        // terminal NoKeyWorked (not fall through). Uses an empty key store so the
        // outcome is deterministic — a *random* wrong RSA key would clear the
        // `[-17]==0` unwrap check ~1/256 of the time and flake.
        let book_key = [0x01u8; 16];
        let (_der, license) = adept_keys(&book_key);
        let pdf = build_ebx_pdf(&book_key, 2, 4, &license, b"x", b"y");

        assert!(matches!(
            crate::decrypt(&pdf, "pdf", &KeyStore::default()),
            Err(SchemeError::NoKeyWorked)
        ));
    }

    #[test]
    fn unencrypted_pdf_is_not_claimed() {
        // No /Encrypt: both PDF handlers fall through → overall NoKeyWorked.
        let mut pdf = Vec::new();
        pdf.extend_from_slice(b"%PDF-1.4\n");
        let o1 = pdf.len();
        pdf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog >>\nendobj\n");
        let xref = pdf.len();
        pdf.extend_from_slice(b"xref\n0 2\n0000000000 65535 f \n");
        pdf.extend_from_slice(format!("{o1:010} 00000 n \n").as_bytes());
        pdf.extend_from_slice(b"trailer\n<< /Size 2 /Root 1 0 R >>\n");
        pdf.extend_from_slice(format!("startxref\n{xref}\n%%EOF").as_bytes());

        assert!(matches!(
            crate::decrypt(&pdf, "pdf", &KeyStore::default()),
            Err(SchemeError::NoKeyWorked)
        ));
    }
}
