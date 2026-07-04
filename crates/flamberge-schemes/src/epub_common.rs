//! Shared OCF/EPUB decryption helpers used by both the Adobe ADEPT (§7.3) and
//! Barnes & Noble (§4.4) schemes. The two differ only in how the book key is
//! unwrapped; the per-file member decryption and base64 handling are identical.
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §4.4 / §7.3.

use std::io::Read;

use base64::Engine;
use flamberge_crypto::{aes, kdf};

use crate::{Result, SchemeError};

/// Decrypt one encrypted OCF member with a recovered 16-byte book key.
///
/// AES-128-CBC with IV = the first 16 ciphertext bytes over the remainder. This
/// is exactly the reference schemes' "decrypt the whole blob with a zero IV,
/// then drop the first 16 plaintext bytes": CBC block `i` is `D(Cᵢ) ⊕ Cᵢ₋₁`, so
/// keying the first stored block in as the IV yields the same blocks 1..n while
/// discarding block 0. Then strip PKCS#7 and raw inflate. A member that was
/// stored (not deflated) fails inflate and passes through unchanged (§4.4/§7.3).
pub(crate) fn decrypt_member(book_key: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 16 || data.len() % 16 != 0 {
        return Err(invalid(
            "EPUB encrypted member is not a whole number of AES blocks",
        ));
    }
    let (iv, ciphertext) = data.split_at(16);
    let plain = aes::cbc_decrypt(book_key, iv, ciphertext)?;
    let plain = kdf::pkcs7_unpad(&plain, 16)?;
    Ok(raw_inflate(&plain).unwrap_or(plain))
}

/// Raw DEFLATE inflate (RFC 1951, zlib `windowBits = -15`). Returns `None` on any
/// error so the caller passes the bytes through unchanged, matching the reference
/// `decompress`'s bare `except: return bytes`.
pub(crate) fn raw_inflate(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::DeflateDecoder::new(data)
        .read_to_end(&mut out)
        .ok()
        .map(|_| out)
}

/// Decode base64, tolerating embedded whitespace as the reference codec does.
pub(crate) fn decode_b64(s: &str) -> Result<Vec<u8>> {
    let compact: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(compact.as_bytes())
        .map_err(|e| invalid(&format!("invalid base64 wrapped key: {e}")))
}

/// Wrap a message in a `FormatError::Invalid` scheme error.
pub(crate) fn invalid(msg: &str) -> SchemeError {
    SchemeError::Format(flamberge_formats::FormatError::Invalid(msg.to_string()))
}

/// Test-only EPUB fixture builders shared by the ADEPT (§7.3) and B&N (§4.4)
/// scheme test modules.
///
/// Both schemes drive the same production [`decrypt_member`] path, so their
/// synthetic books must be packaged identically — same IV-prefix layout, same
/// `mimetype`-stored ZIP shape, same `rights.xml`/`encryption.xml` structure.
/// Keeping one definition here means a change to how a member is encrypted or how
/// the container is built updates both schemes' fixtures at once, rather than
/// letting the two copies silently drift. Only the *scheme-agnostic* builders
/// live here; each scheme keeps its own key-wrapping and `synth_*_epub` fixture.
#[cfg(test)]
pub(crate) mod test_support {
    use std::collections::BTreeMap;
    use std::io::{Read, Write};

    use flamberge_crypto::aes;
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    /// XML namespace for the Adobe ADEPT `rights.xml` elements.
    pub(crate) const ADEPT_NS: &str = "http://ns.adobe.com/adept";
    /// XML namespace for the W3C XML-Encryption `encryption.xml` elements.
    pub(crate) const ENC_NS: &str = "http://www.w3.org/2001/04/xmlenc#";

    /// Append PKCS#7 padding to a whole block, matching what a real packager
    /// feeds AES before encrypting (§4.4/§7.3).
    pub(crate) fn pkcs7_pad(data: &[u8], block: usize) -> Vec<u8> {
        let pad = block - data.len() % block;
        let mut out = data.to_vec();
        out.extend(std::iter::repeat_n(pad as u8, pad));
        out
    }

    /// Raw DEFLATE (zlib `windowBits = -15`), the inverse of the production
    /// [`super::raw_inflate`].
    pub(crate) fn raw_deflate(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// Encrypt one member as ADEPT/B&N store it: `IV || AES-CBC(book_key, IV,
    /// pkcs7(body))`, where `body` is raw-deflated when `deflate` is set. The
    /// prepended IV block is what [`super::decrypt_member`] drops.
    pub(crate) fn encrypt_member(book_key: &[u8; 16], content: &[u8], deflate: bool) -> Vec<u8> {
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

    /// A minimal `rights.xml` carrying the base64 wrapped book key inside
    /// `adept:licenseToken/adept:encryptedKey`.
    pub(crate) fn rights_xml(key_b64: &str) -> Vec<u8> {
        format!(
            "<?xml version=\"1.0\"?>\
             <adept:rights xmlns:adept=\"{ADEPT_NS}\">\
             <adept:licenseToken><adept:encryptedKey>{key_b64}</adept:encryptedKey>\
             </adept:licenseToken></adept:rights>"
        )
        .into_bytes()
    }

    /// An `encryption.xml` listing each encrypted member path as a
    /// `CipherReference URI`.
    pub(crate) fn encryption_xml(paths: &[&str]) -> Vec<u8> {
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

    /// Build an OCF ZIP from `(name, bytes)` members, storing `mimetype` and
    /// deflating the rest — the container shape the schemes parse and repackage.
    pub(crate) fn build_zip(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
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

    /// Read a ZIP back into a `name -> bytes` map for asserting recovered content.
    pub(crate) fn read_zip(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
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
}
