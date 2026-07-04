//! EPUB / OCF (Open Container Format) helpers for ADEPT and B&N EPUBs.
//!
//! Reads `META-INF/rights.xml` (wrapped book key) and `META-INF/encryption.xml`
//! (which files are encrypted), and repackages a decrypted zip with `mimetype`
//! stored first. This module is **I/O + XML only** — the crypto (RSA/AES unwrap,
//! per-file decrypt) lives in `flamberge-schemes`.
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §7.3 (ADEPT, `ineptepub.py`) and §4.4
//! (Barnes & Noble, `ignobleepub.py`). Both schemes share this container layer
//! and differ only in how the wrapped key is unwrapped.

use std::collections::{BTreeMap, HashSet};
use std::io::{Cursor, Read, Write};

use quick_xml::events::Event;
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;
use zip::result::ZipError;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::{FormatError, Result};

/// Wrapped-key holder in an ADEPT/B&N EPUB.
pub const RIGHTS_XML: &str = "META-INF/rights.xml";
/// Manifest of which members are encrypted.
pub const ENCRYPTION_XML: &str = "META-INF/encryption.xml";
/// The uncompressed, always-first OCF media-type member.
pub const MIMETYPE: &str = "mimetype";

/// Adobe ADEPT XML namespace.
pub const NS_ADEPT: &[u8] = b"http://ns.adobe.com/adept";
/// W3C XML-Encryption namespace.
pub const NS_ENC: &[u8] = b"http://www.w3.org/2001/04/xmlenc#";

/// Length in base64 chars of an ADEPT wrapped key (128-byte / 1024-bit RSA block).
pub const ADEPT_KEY_LEN: usize = 172;
/// Length in base64 chars of a Barnes & Noble wrapped key (48-byte AES block).
pub const BN_KEY_LEN: usize = 64;

/// Which EPUB DRM scheme a parsed container looks like, inferred from the
/// wrapped-key length (§7.3 vs §4.4). Both schemes present identical META-INF
/// markers, so the length is the only offline discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpubScheme {
    /// Adobe ADEPT: 172-char wrapped key, unwrapped with 1024-bit RSA.
    Adept,
    /// Barnes & Noble: 64-char wrapped key, unwrapped with AES-128-CBC.
    BarnesNoble,
}

/// Parsed DRM metadata from an EPUB's META-INF files.
#[derive(Debug, Default)]
pub struct OcfEncryption {
    /// Base64 text of the wrapped book key from `rights.xml`
    /// (`.//{adept}encryptedKey`), stored verbatim so its length still
    /// discriminates ADEPT (172) from B&N (64) as in the reference plugins.
    pub wrapped_key_b64: Option<String>,
    /// Set of member paths listed as encrypted in `encryption.xml`
    /// (`{enc}CipherReference@URI`).
    pub encrypted_paths: HashSet<String>,
}

impl OcfEncryption {
    /// Parse `rights.xml` + `encryption.xml` from an EPUB zip image. Missing
    /// members are treated as absent (not an error); use [`is_encrypted_epub`]
    /// or [`OcfEncryption::scheme`] to decide whether the book is actually
    /// DRM-protected.
    pub fn parse(zip_data: &[u8]) -> Result<Self> {
        let mut archive =
            ZipArchive::new(Cursor::new(zip_data)).map_err(|e| zip_error("open archive", e))?;

        let mut out = OcfEncryption::default();
        if let Some(rights) = read_optional_member(&mut archive, RIGHTS_XML)? {
            out.wrapped_key_b64 = extract_encrypted_key(&rights)?;
        }
        if let Some(encryption) = read_optional_member(&mut archive, ENCRYPTION_XML)? {
            out.encrypted_paths = extract_cipher_references(&encryption)?;
        }
        Ok(out)
    }

    /// Infer the DRM scheme from the wrapped-key length: 172 → ADEPT, 64 → B&N,
    /// anything else (including a missing key) → `None`.
    pub fn scheme(&self) -> Option<EpubScheme> {
        match self.wrapped_key_b64.as_deref().map(str::len) {
            Some(ADEPT_KEY_LEN) => Some(EpubScheme::Adept),
            Some(BN_KEY_LEN) => Some(EpubScheme::BarnesNoble),
            _ => None,
        }
    }
}

/// True if the EPUB carries both ADEPT/B&N META-INF markers
/// (`rights.xml` **and** `encryption.xml`). Mirrors the presence guard the
/// reference plugins use before attempting decryption; a `false` result means
/// "DRM-free / not this scheme".
pub fn is_encrypted_epub(zip_data: &[u8]) -> Result<bool> {
    let archive =
        ZipArchive::new(Cursor::new(zip_data)).map_err(|e| zip_error("open archive", e))?;
    let names: HashSet<&str> = archive.file_names().collect();
    Ok(names.contains(RIGHTS_XML) && names.contains(ENCRYPTION_XML))
}

/// Decompress every member into `(name, bytes)` pairs in archive order. The
/// scheme layer uses this to obtain ciphertext for the encrypted members before
/// handing decrypted replacements back to [`repackage`].
pub fn read_all_members(zip_data: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let mut archive =
        ZipArchive::new(Cursor::new(zip_data)).map_err(|e| zip_error("open archive", e))?;

    let mut members = Vec::with_capacity(archive.len());
    for i in 0..archive.len() {
        let mut member = archive
            .by_index(i)
            .map_err(|e| zip_error("read member", e))?;
        let name = member.name().to_owned();
        let mut bytes = Vec::new();
        member.read_to_end(&mut bytes)?;
        members.push((name, bytes));
    }
    Ok(members)
}

/// Rebuild the EPUB from `original`, substituting decrypted bytes for the
/// members named in `replacements` and copying the rest. Per OCF/DeDRM rules
/// (§7.3): `mimetype` is written first and **stored** (uncompressed), every
/// other member is **deflated**, entry timestamps and unix permissions are
/// preserved, and `rights.xml`/`encryption.xml` are dropped.
pub fn repackage(original: &[u8], replacements: &BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>> {
    let mut archive =
        ZipArchive::new(Cursor::new(original)).map_err(|e| zip_error("open archive", e))?;

    let mut buf = Vec::new();
    {
        let mut writer = ZipWriter::new(Cursor::new(&mut buf));

        // OCF requires `mimetype` first and stored so the media type can be
        // sniffed at a fixed offset without inflating.
        if let Some(idx) = archive.index_for_name(MIMETYPE) {
            let (bytes, options) = member_for_output(
                &mut archive,
                idx,
                MIMETYPE,
                replacements,
                CompressionMethod::Stored,
            )?;
            writer
                .start_file(MIMETYPE, options)
                .map_err(|e| zip_error("start mimetype", e))?;
            writer.write_all(&bytes)?;
        }

        for i in 0..archive.len() {
            let name = archive
                .by_index(i)
                .map_err(|e| zip_error("read member", e))?
                .name()
                .to_owned();

            // `mimetype` is already written; the two META-INF DRM files are
            // dropped from the decrypted output.
            if name == MIMETYPE || name == RIGHTS_XML || name == ENCRYPTION_XML {
                continue;
            }

            let (bytes, options) = member_for_output(
                &mut archive,
                i,
                &name,
                replacements,
                CompressionMethod::Deflated,
            )?;
            writer
                .start_file(&name, options)
                .map_err(|e| zip_error("start member", e))?;
            writer.write_all(&bytes)?;
        }

        writer
            .finish()
            .map_err(|e| zip_error("finish archive", e))?;
    }
    Ok(buf)
}

/// Resolve the output bytes + [`SimpleFileOptions`] for one member: use the
/// decrypted replacement if present, otherwise the member's own content, and
/// carry over the original last-modified time and unix permissions.
fn member_for_output(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    index: usize,
    name: &str,
    replacements: &BTreeMap<String, Vec<u8>>,
    compression: CompressionMethod,
) -> Result<(Vec<u8>, SimpleFileOptions)> {
    let mut member = archive
        .by_index(index)
        .map_err(|e| zip_error("read member", e))?;

    let mut options = SimpleFileOptions::default().compression_method(compression);
    if let Some(mtime) = member.last_modified() {
        options = options.last_modified_time(mtime);
    }
    if let Some(mode) = member.unix_mode() {
        options = options.unix_permissions(mode);
    }

    let bytes = match replacements.get(name) {
        Some(replacement) => replacement.clone(),
        None => {
            let mut b = Vec::new();
            member.read_to_end(&mut b)?;
            b
        }
    };
    Ok((bytes, options))
}

/// Read a member by name, returning `None` if it is absent and propagating any
/// other zip error.
fn read_optional_member(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    name: &str,
) -> Result<Option<Vec<u8>>> {
    match archive.by_name(name) {
        Ok(mut member) => {
            let mut bytes = Vec::new();
            member.read_to_end(&mut bytes)?;
            Ok(Some(bytes))
        }
        Err(ZipError::FileNotFound) => Ok(None),
        Err(e) => Err(zip_error("read member", e)),
    }
}

/// Extract the text of the first `{adept}encryptedKey` element anywhere in
/// `rights.xml`. Returns the text verbatim (untrimmed) so its length preserves
/// the ADEPT/B&N discriminator.
fn extract_encrypted_key(xml: &[u8]) -> Result<Option<String>> {
    let mut reader = NsReader::from_reader(xml);
    let mut buf = Vec::new();
    let mut capturing = false;
    let mut text = String::new();

    loop {
        match reader
            .read_resolved_event_into(&mut buf)
            .map_err(xml_error)?
        {
            (ns, Event::Start(e)) => {
                if is_named(ns, e.local_name().as_ref(), NS_ADEPT, b"encryptedKey") {
                    capturing = true;
                    text.clear();
                }
            }
            (_, Event::Text(e)) if capturing => {
                let chunk = e.unescape().map_err(xml_error)?;
                text.push_str(&chunk);
            }
            (ns, Event::End(e)) if capturing => {
                if is_named(ns, e.local_name().as_ref(), NS_ADEPT, b"encryptedKey") {
                    return Ok(Some(text));
                }
            }
            (_, Event::Eof) => return Ok(None),
            _ => {}
        }
        buf.clear();
    }
}

/// Collect every `{enc}CipherReference@URI` value from `encryption.xml`.
fn extract_cipher_references(xml: &[u8]) -> Result<HashSet<String>> {
    let mut reader = NsReader::from_reader(xml);
    let mut buf = Vec::new();
    let mut paths = HashSet::new();

    loop {
        let (ns, event) = reader
            .read_resolved_event_into(&mut buf)
            .map_err(xml_error)?;
        match event {
            Event::Start(ref e) | Event::Empty(ref e) => {
                if is_named(ns, e.local_name().as_ref(), NS_ENC, b"CipherReference") {
                    if let Some(attr) = e.try_get_attribute(b"URI").map_err(xml_error)? {
                        let uri = attr.unescape_value().map_err(xml_error)?;
                        paths.insert(uri.into_owned());
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(paths)
}

/// True if a resolved element is in namespace `ns` with local name `local`.
fn is_named(resolved: ResolveResult, local: &[u8], ns: &[u8], local_name: &[u8]) -> bool {
    matches!(resolved, ResolveResult::Bound(bound) if bound.as_ref() == ns) && local == local_name
}

fn xml_error(err: quick_xml::Error) -> FormatError {
    FormatError::Invalid(format!("ocf xml: {err}"))
}

fn zip_error(ctx: &str, err: ZipError) -> FormatError {
    FormatError::Invalid(format!("ocf {ctx}: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADEPT_NS: &str = "http://ns.adobe.com/adept";
    const ENC_NS: &str = "http://www.w3.org/2001/04/xmlenc#";

    fn rights_xml(key: &str) -> Vec<u8> {
        format!(
            "<?xml version=\"1.0\"?>\
             <adept:rights xmlns:adept=\"{ADEPT_NS}\">\
             <adept:licenseToken>\
             <adept:encryptedKey>{key}</adept:encryptedKey>\
             </adept:licenseToken>\
             </adept:rights>"
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

    /// Build a synthetic EPUB. `mimetype` is written first, matching a real OCF.
    fn build_epub(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut writer = ZipWriter::new(Cursor::new(&mut buf));
            for (name, bytes) in members {
                let method = if *name == MIMETYPE {
                    CompressionMethod::Stored
                } else {
                    CompressionMethod::Deflated
                };
                let options = SimpleFileOptions::default().compression_method(method);
                writer.start_file(*name, options).unwrap();
                writer.write_all(bytes).unwrap();
            }
            writer.finish().unwrap();
        }
        buf
    }

    fn adept_epub() -> Vec<u8> {
        build_epub(&[
            (MIMETYPE, b"application/epub+zip".to_vec()),
            (RIGHTS_XML, rights_xml(&"A".repeat(ADEPT_KEY_LEN))),
            (ENCRYPTION_XML, encryption_xml(&["OEBPS/ch1.html"])),
            ("OEBPS/ch1.html", b"CIPHERTEXT".to_vec()),
            ("OEBPS/style.css", b"body{}".to_vec()),
        ])
    }

    #[test]
    fn parse_extracts_wrapped_key_and_encrypted_paths() {
        let parsed = OcfEncryption::parse(&adept_epub()).unwrap();
        assert_eq!(parsed.wrapped_key_b64.as_deref(), Some(&*"A".repeat(172)));
        assert!(parsed.encrypted_paths.contains("OEBPS/ch1.html"));
        assert_eq!(parsed.encrypted_paths.len(), 1);
    }

    #[test]
    fn detects_adept_by_key_length() {
        let parsed = OcfEncryption::parse(&adept_epub()).unwrap();
        assert_eq!(parsed.scheme(), Some(EpubScheme::Adept));
    }

    #[test]
    fn detects_barnes_noble_by_key_length() {
        let epub = build_epub(&[
            (MIMETYPE, b"application/epub+zip".to_vec()),
            (RIGHTS_XML, rights_xml(&"B".repeat(BN_KEY_LEN))),
            (ENCRYPTION_XML, encryption_xml(&["a.html"])),
            ("a.html", b"x".to_vec()),
        ]);
        let parsed = OcfEncryption::parse(&epub).unwrap();
        assert_eq!(parsed.scheme(), Some(EpubScheme::BarnesNoble));
    }

    #[test]
    fn unknown_key_length_is_no_scheme() {
        let epub = build_epub(&[
            (MIMETYPE, b"application/epub+zip".to_vec()),
            (RIGHTS_XML, rights_xml("SHORT")),
            (ENCRYPTION_XML, encryption_xml(&[])),
        ]);
        let parsed = OcfEncryption::parse(&epub).unwrap();
        assert_eq!(parsed.scheme(), None);
    }

    #[test]
    fn plain_epub_reports_not_encrypted() {
        let epub = build_epub(&[
            (MIMETYPE, b"application/epub+zip".to_vec()),
            ("OEBPS/ch1.html", b"<html/>".to_vec()),
        ]);
        assert!(!is_encrypted_epub(&epub).unwrap());
        let parsed = OcfEncryption::parse(&epub).unwrap();
        assert!(parsed.wrapped_key_b64.is_none());
        assert!(parsed.encrypted_paths.is_empty());
        assert_eq!(parsed.scheme(), None);
    }

    #[test]
    fn encrypted_epub_is_detected() {
        assert!(is_encrypted_epub(&adept_epub()).unwrap());
    }

    #[test]
    fn read_all_members_decompresses_in_order() {
        let members = read_all_members(&adept_epub()).unwrap();
        let names: Vec<&str> = members.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names[0], MIMETYPE);
        let ch1 = members.iter().find(|(n, _)| n == "OEBPS/ch1.html").unwrap();
        assert_eq!(ch1.1, b"CIPHERTEXT");
    }

    #[test]
    fn repackage_places_mimetype_first_stored_and_drops_meta() {
        let mut replacements = BTreeMap::new();
        replacements.insert("OEBPS/ch1.html".to_owned(), b"<html>plain</html>".to_vec());
        let rebuilt = repackage(&adept_epub(), &replacements).unwrap();

        let mut archive = ZipArchive::new(Cursor::new(rebuilt)).unwrap();

        // mimetype is entry 0 and stored.
        {
            let first = archive.by_index(0).unwrap();
            assert_eq!(first.name(), MIMETYPE);
            assert_eq!(first.compression(), CompressionMethod::Stored);
        }

        let mut names = Vec::new();
        let mut contents = BTreeMap::new();
        for i in 0..archive.len() {
            let mut f = archive.by_index(i).unwrap();
            let name = f.name().to_owned();
            let mut bytes = Vec::new();
            f.read_to_end(&mut bytes).unwrap();
            names.push(name.clone());
            contents.insert(name, bytes);
        }

        // DRM META files are gone; the decrypted member replaced the ciphertext;
        // untouched members survive verbatim.
        assert!(!names.contains(&RIGHTS_XML.to_owned()));
        assert!(!names.contains(&ENCRYPTION_XML.to_owned()));
        assert_eq!(contents["OEBPS/ch1.html"], b"<html>plain</html>");
        assert_eq!(contents["OEBPS/style.css"], b"body{}");
        assert_eq!(contents[MIMETYPE], b"application/epub+zip");
    }

    #[test]
    fn repackage_deflates_non_mimetype_members() {
        let rebuilt = repackage(&adept_epub(), &BTreeMap::new()).unwrap();
        let mut archive = ZipArchive::new(Cursor::new(rebuilt)).unwrap();
        for i in 0..archive.len() {
            let f = archive.by_index(i).unwrap();
            if f.name() == MIMETYPE {
                assert_eq!(f.compression(), CompressionMethod::Stored);
            } else {
                assert_eq!(f.compression(), CompressionMethod::Deflated);
            }
        }
    }

    #[test]
    fn repackage_preserves_timestamp_and_permissions() {
        let mtime = zip::DateTime::from_date_and_time(2021, 6, 15, 8, 30, 20).unwrap();
        let mut original = Vec::new();
        {
            let mut writer = ZipWriter::new(Cursor::new(&mut original));
            let mimetype_opts = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Stored)
                .last_modified_time(mtime);
            writer.start_file(MIMETYPE, mimetype_opts).unwrap();
            writer.write_all(b"application/epub+zip").unwrap();

            let member_opts = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .last_modified_time(mtime)
                .unix_permissions(0o644);
            writer.start_file("OEBPS/ch1.html", member_opts).unwrap();
            writer.write_all(b"<html/>").unwrap();
            writer.finish().unwrap();
        }

        let rebuilt = repackage(&original, &BTreeMap::new()).unwrap();
        let mut archive = ZipArchive::new(Cursor::new(rebuilt)).unwrap();
        let member = archive.by_name("OEBPS/ch1.html").unwrap();
        assert_eq!(member.last_modified(), Some(mtime));
        // The reader reports the full mode including the regular-file type bits.
        assert_eq!(member.unix_mode(), Some(0o100644));
    }
}
