//! Topaz `TPZ0` container parsing.
//!
//! Layout: `"TPZ0"` magic, a header of named records (each `0x63` + name +
//! `[offset, decompLen, compLen]` triples), a `0x64` end marker at
//! `book_payload_offset`, then payload records addressed relative to that
//! offset. Payload record index is negative when encrypted.
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §5.2.  **STUB.**

use crate::{FormatError, Result};

pub const MAGIC: &[u8; 4] = b"TPZ0";
pub const HEADER_RECORD_MARKER: u8 = 0x63; // 'c'
pub const END_OF_HEADERS_MARKER: u8 = 0x64; // 'd'

/// One `[offset, decompressed_len, compressed_len]` header triple.
/// `compressed_len == 0` means the payload record is stored uncompressed.
#[derive(Debug, Clone, Copy)]
pub struct RecordEntry {
    pub offset: u64,
    pub decompressed_len: u64,
    pub compressed_len: u64,
}

#[derive(Debug, Default)]
pub struct TopazContainer {
    /// Header records keyed by name (e.g. `metadata`, `dkey`, `page`, `glyphs`).
    pub header_records: std::collections::HashMap<Vec<u8>, Vec<RecordEntry>>,
    pub book_payload_offset: u64,
}

impl TopazContainer {
    pub fn parse(_data: &[u8]) -> Result<Self> {
        // TODO(topaz): read variable-length encoded numbers (§5.1), the header
        // record list (§5.2), and resolve `book_payload_offset`.
        Err(FormatError::Unimplemented("topaz_container::parse"))
    }
}

/// Read a Topaz variable-length "encoded number" (big-endian base-128, optional
/// leading `0xFF` negative marker). Returns `(value, bytes_consumed)`.
/// Reference: `docs/DEDRM_SCHEMES.md` §5.1.  **STUB.**
pub fn read_encoded_number(_data: &[u8]) -> Result<(i64, usize)> {
    Err(FormatError::Unimplemented(
        "topaz_container::read_encoded_number",
    ))
}
