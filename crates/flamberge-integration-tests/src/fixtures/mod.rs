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

use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

pub mod epub;
pub mod ereader;
pub mod kfx;
pub mod kobo;
pub mod mobipocket;
pub mod pdf;
pub mod topaz;

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
