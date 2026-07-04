//! PDF tokenizer / object model for ADEPT (`EBX_HANDLER`) and B&N PDFs.
//!
//! A faithful, in-memory port of the pdfminer-derived parser in `ineptpdf.py`.
//! Concerns are split across submodules:
//!
//! - [`object`] — the parsed object model ([`Object`], [`PdfStream`], [`Dict`]).
//! - [`lexer`] — the byte-cursor tokenizer.
//! - [`parser`] — the recursive-descent object parser (tokens → [`Object`]).
//! - [`filters`] — stream decoding: `FlateDecode` / `LZWDecode` / `ASCII85Decode`
//!   plus the TIFF/PNG predictors.
//! - [`document`] — [`PdfDocument`]: the cross-reference chain (classic `xref`
//!   tables **and** PDF-1.5 xref streams), object streams (`ObjStm`), the merged
//!   trailer, and lazy object resolution.
//! - [`serializer`] — [`PdfSerializer`]: re-emit a clean PDF (classic xref,
//!   generation numbers forced to 0, `/Encrypt` dropped).
//!
//! The *crypto* is intentionally out of scope here: the `/Encrypt` dict and
//! `/ID` are exposed for the scheme layer, which supplies a [`Decipher`] closure
//! (an MD5-derived per-object RC4/AES key) via [`PdfDocument::set_decipher`].
//! This module only provides the plumbing that walks each uncompressed object
//! and applies that closure to its string/stream bytes.
//!
//! Where `ineptpdf.py` streams bytes through a buffer-refilling `PSBaseParser`
//! (a workaround for Python file I/O), this port keeps the whole document in a
//! `Vec<u8>` and drives a simple cursor — the token grammar is identical.
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §7.4. Original: `ineptpdf.py`.

mod document;
mod filters;
mod lexer;
mod object;
mod parser;
mod serializer;

pub use document::{Decipher, PdfDocument};
pub use object::{Dict, Object, PdfStream};
pub use serializer::PdfSerializer;

/// The three ADEPT/B&N `/Encrypt` `/Filter` values.
pub const FILTER_STANDARD: &str = "Standard";
pub const FILTER_ADOBE_APS: &str = "Adobe.APS";
pub const FILTER_EBX_HANDLER: &str = "EBX_HANDLER";
