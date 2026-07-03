//! PDF tokenizer / object model for ADEPT (`EBX_HANDLER`) and B&N PDFs.
//!
//! A pdfminer-style parser: classic `xref` tables + PDF-1.5 xref streams +
//! object streams, filters Flate/LZW/ASCII85. The `/Encrypt` dict carries the
//! DRM parameters (`Filter`, `V`, `Length`, `ADEPT_LICENSE`, ...). Content is
//! deciphered per-object (RC4 or AES) with an MD5-derived object key.
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §7.4.  **STUB** (large; port incrementally).

use crate::{FormatError, Result};

/// The three ADEPT/B&N `/Encrypt` `/Filter` values.
pub const FILTER_STANDARD: &str = "Standard";
pub const FILTER_ADOBE_APS: &str = "Adobe.APS";
pub const FILTER_EBX_HANDLER: &str = "EBX_HANDLER";

#[derive(Debug, Default)]
pub struct PdfDocument {
    // TODO(pdf): object table, xref, trailer, /Encrypt dict.
}

impl PdfDocument {
    pub fn parse(_data: &[u8]) -> Result<Self> {
        Err(FormatError::Unimplemented("pdf::PdfDocument::parse"))
    }
}
