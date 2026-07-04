//! KFX-ZIP container: locate the DRMION content member and the DRM voucher
//! member by leading magic (not filename), and repackage the archive with
//! decrypted members substituted in.
//!
//! This module performs **no decryption** — it only splits the container apart
//! and puts it back together. The voucher unwrap and page decryption live in
//! `flamberge-schemes::kfx`. Reference: `docs/DEDRM_SCHEMES.md` §3.1.

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};

use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::{FormatError, Result};

/// DRMION content member prefix (`\xeaDRMION\xee`). Payload is `member[8..len-8]`.
pub const DRMION_MAGIC: &[u8; 8] = b"\xeaDRMION\xee";
/// Amazon ION binary version marker; also the voucher member's leading bytes.
pub const ION_BVM: &[u8; 4] = b"\xe0\x01\x00\xea";
/// ASCII sentinel that identifies the voucher member among ION streams.
pub const VOUCHER_SENTINEL: &[u8] = b"ProtectedData";

#[derive(Debug, Default)]
pub struct KfxZip {
    /// (member name, DRMION payload with the 8-byte prefix/suffix stripped).
    pub drmion_members: Vec<(String, Vec<u8>)>,
    /// Raw voucher member bytes (including the BVM), if found.
    pub voucher: Option<Vec<u8>>,
}

impl KfxZip {
    /// Scan every zip member by **leading magic** (§3.1): DRMION content members
    /// are collected with their 8-byte prefix/suffix stripped
    /// (`kfxdedrm.py::processBook` reads `data[8:-8]`), and the first ION member
    /// containing the `ProtectedData` sentinel is kept as the voucher
    /// (`decrypt_voucher`). Non-matching members are ignored here.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut archive =
            ZipArchive::new(Cursor::new(data)).map_err(|e| zip_error("open archive", e))?;

        let mut out = KfxZip::default();
        for i in 0..archive.len() {
            let mut member = archive
                .by_index(i)
                .map_err(|e| zip_error("read member", e))?;
            let name = member.name().to_owned();
            let mut bytes = Vec::with_capacity(member.size() as usize);
            member.read_to_end(&mut bytes)?;

            if bytes.starts_with(DRMION_MAGIC) {
                if bytes.len() < DRMION_MAGIC.len() + 8 {
                    return Err(FormatError::Invalid(format!(
                        "DRMION member {name} is too short to strip 8+8 bytes"
                    )));
                }
                let payload = bytes[8..bytes.len() - 8].to_vec();
                out.drmion_members.push((name, payload));
            } else if bytes.starts_with(ION_BVM)
                && out.voucher.is_none()
                && contains_subslice(&bytes, VOUCHER_SENTINEL)
            {
                out.voucher = Some(bytes);
            }
        }

        Ok(out)
    }
}

/// Rebuild the archive from `original`, replacing the members named in
/// `replacements` with the supplied (decrypted) bytes and copying every other
/// member verbatim. Mirrors `kfxdedrm.py::KFXZipBook.getFile`.
pub fn repackage(original: &[u8], replacements: &BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>> {
    let mut archive =
        ZipArchive::new(Cursor::new(original)).map_err(|e| zip_error("open archive", e))?;

    let mut buf = Vec::new();
    {
        let mut writer = ZipWriter::new(Cursor::new(&mut buf));
        for i in 0..archive.len() {
            let name = archive
                .by_index(i)
                .map_err(|e| zip_error("read member", e))?
                .name()
                .to_owned();

            if let Some(bytes) = replacements.get(&name) {
                let options =
                    SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
                writer
                    .start_file(name, options)
                    .map_err(|e| zip_error("start member", e))?;
                writer.write_all(bytes)?;
            } else {
                let raw = archive
                    .by_index_raw(i)
                    .map_err(|e| zip_error("read raw member", e))?;
                writer
                    .raw_copy_file(raw)
                    .map_err(|e| zip_error("copy member", e))?;
            }
        }
        writer
            .finish()
            .map_err(|e| zip_error("finish archive", e))?;
    }

    Ok(buf)
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn zip_error(ctx: &str, err: zip::result::ZipError) -> FormatError {
    FormatError::Invalid(format!("kfx-zip {ctx}: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_zip(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut writer = ZipWriter::new(Cursor::new(&mut buf));
            let options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            for (name, bytes) in members {
                writer.start_file(*name, options).unwrap();
                writer.write_all(bytes).unwrap();
            }
            writer.finish().unwrap();
        }
        buf
    }

    fn drmion_member(payload: &[u8]) -> Vec<u8> {
        let mut v = DRMION_MAGIC.to_vec();
        v.extend_from_slice(payload);
        v.extend_from_slice(b"\x00\x00\x00\x00\x00\x00\x00\x00"); // 8-byte suffix
        v
    }

    fn voucher_member() -> Vec<u8> {
        let mut v = ION_BVM.to_vec();
        v.extend_from_slice(b"....ProtectedData....");
        v
    }

    #[test]
    fn parse_locates_drmion_and_voucher_by_magic() {
        let zip = build_zip(&[
            ("resources/plain.txt", b"hello".to_vec()),
            ("book/content.drmion", drmion_member(b"PAGES")),
            ("book/voucher.ion", voucher_member()),
        ]);

        let parsed = KfxZip::parse(&zip).unwrap();
        assert_eq!(parsed.drmion_members.len(), 1);
        assert_eq!(parsed.drmion_members[0].0, "book/content.drmion");
        assert_eq!(parsed.drmion_members[0].1, b"PAGES"); // 8+8 stripped
        let voucher = parsed.voucher.expect("voucher present");
        assert!(voucher.starts_with(ION_BVM));
    }

    #[test]
    fn ion_member_without_sentinel_is_not_the_voucher() {
        let mut not_voucher = ION_BVM.to_vec();
        not_voucher.extend_from_slice(b"just some ion bytes");
        let zip = build_zip(&[("x.ion", not_voucher)]);
        let parsed = KfxZip::parse(&zip).unwrap();
        assert!(parsed.voucher.is_none());
        assert!(parsed.drmion_members.is_empty());
    }

    #[test]
    fn repackage_substitutes_named_members_and_copies_the_rest() {
        let zip = build_zip(&[
            ("resources/plain.txt", b"hello".to_vec()),
            ("book/content.drmion", drmion_member(b"CIPHERTEXT")),
        ]);

        let mut replacements = BTreeMap::new();
        replacements.insert("book/content.drmion".to_owned(), b"DECRYPTED".to_vec());
        let rebuilt = repackage(&zip, &replacements).unwrap();

        let mut archive = ZipArchive::new(Cursor::new(rebuilt)).unwrap();
        let mut got = BTreeMap::new();
        for i in 0..archive.len() {
            let mut f = archive.by_index(i).unwrap();
            let name = f.name().to_owned();
            let mut bytes = Vec::new();
            f.read_to_end(&mut bytes).unwrap();
            got.insert(name, bytes);
        }
        assert_eq!(got["resources/plain.txt"], b"hello");
        assert_eq!(got["book/content.drmion"], b"DECRYPTED");
    }

    #[test]
    fn drmion_member_too_short_is_rejected() {
        let mut short = DRMION_MAGIC.to_vec();
        short.extend_from_slice(b"1234"); // < 8-byte suffix available
        let zip = build_zip(&[("s.drmion", short)]);
        assert!(KfxZip::parse(&zip).is_err());
    }
}
