//! PMLZ container writer — the output package for decrypted eReader books.
//!
//! A `.pmlz` is a plain ZIP archive (all members **stored**, no compression)
//! holding the book's `<name>.pml` at the root plus an `images/` folder of
//! extracted illustrations. DropBook and Calibre both ingest this layout.
//! This module only serializes bytes into that container — the eReader crypto
//! lives in `flamberge-schemes`. Reference: `docs/DEDRM_SCHEMES.md` §8
//! (`erdr2pml.py::decryptBook`, the `--make-pmlz` path).

use std::io::{Cursor, Write};

use zip::result::ZipError;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

use crate::{FormatError, Result};

fn zip_error(ctx: &str, err: ZipError) -> FormatError {
    FormatError::Invalid(format!("pmlz {ctx}: {err}"))
}

/// Build a `.pmlz` archive: `pml_name` (e.g. `book.pml`) at the root carrying
/// `pml`, and each `(name, bytes)` in `images` written under `images/<name>`.
/// Every entry is stored uncompressed, matching `erdr2pml.py`'s `ZIP_STORED`.
pub fn write(pml_name: &str, pml: &[u8], images: &[(String, Vec<u8>)]) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    {
        let mut writer = ZipWriter::new(Cursor::new(&mut buf));
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);

        writer
            .start_file(pml_name, options)
            .map_err(|e| zip_error("start pml", e))?;
        writer.write_all(pml)?;

        for (name, data) in images {
            writer
                .start_file(format!("images/{name}"), options)
                .map_err(|e| zip_error("start image", e))?;
            writer.write_all(data)?;
        }

        writer
            .finish()
            .map_err(|e| zip_error("finish archive", e))?;
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use zip::ZipArchive;

    #[test]
    fn round_trips_pml_and_images_all_stored() {
        let images = vec![
            ("cover.png".to_string(), b"\x89PNG-cover".to_vec()),
            ("fig1.jpg".to_string(), b"\xff\xd8-fig".to_vec()),
        ];
        let archive_bytes = write("book.pml", b"\\a233 hello", &images).unwrap();

        let mut zip = ZipArchive::new(Cursor::new(archive_bytes)).unwrap();
        assert_eq!(zip.len(), 3);

        let mut read_entry = |name: &str| {
            let mut f = zip.by_name(name).unwrap();
            assert_eq!(f.compression(), CompressionMethod::Stored);
            let mut out = Vec::new();
            f.read_to_end(&mut out).unwrap();
            out
        };
        assert_eq!(read_entry("book.pml"), b"\\a233 hello");
        assert_eq!(read_entry("images/cover.png"), b"\x89PNG-cover");
        assert_eq!(read_entry("images/fig1.jpg"), b"\xff\xd8-fig");
    }
}
