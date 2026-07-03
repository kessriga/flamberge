//! Topaz `TPZ0` container parsing.
//!
//! Layout: `"TPZ0"` magic, a header of named records (each `0x63` + name +
//! `[offset, decompLen, compLen]` triples), a `0x64` end marker at
//! `book_payload_offset`, then payload records addressed relative to that
//! offset. A payload record's encoded index is negative when the record is
//! encrypted. This module is the **data layer**: it locates and returns raw
//! record bytes; Topaz decryption and zlib inflate live in `flamberge-schemes`.
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §5.1–5.2. Original: `topazextract.py`
//! (`bookReadEncodedNumber`, `parseTopazHeaders`, `getBookPayloadRecord`,
//! `parseMetadata`).

use std::collections::{BTreeMap, HashMap};

use crate::{FormatError, Result};

/// Container magic at offset 0.
pub const MAGIC: &[u8; 4] = b"TPZ0";
/// Marker byte introducing each named header record.
pub const HEADER_RECORD_MARKER: u8 = 0x63; // 'c'
/// Marker byte ending the header block; the following byte is
/// `book_payload_offset`.
pub const END_OF_HEADERS_MARKER: u8 = 0x64; // 'd'

/// One `[offset, decompressed_len, compressed_len]` header triple.
/// `compressed_len == 0` means the payload record is stored uncompressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordEntry {
    /// Byte offset of the payload record, relative to `book_payload_offset`.
    pub offset: u64,
    /// Length of the record after zlib inflate.
    pub decompressed_len: u64,
    /// Length of the stored (compressed) record, or `0` if uncompressed.
    pub compressed_len: u64,
}

impl RecordEntry {
    /// Whether the payload record is zlib-compressed (`compressed_len > 0`).
    pub fn is_compressed(&self) -> bool {
        self.compressed_len > 0
    }
}

/// A parsed TPZ0 header: the named record table plus the payload base offset.
#[derive(Debug, Default)]
pub struct TopazContainer {
    /// Header records keyed by name (e.g. `metadata`, `dkey`, `page`, `glyphs`).
    pub header_records: HashMap<Vec<u8>, Vec<RecordEntry>>,
    /// Absolute file offset of the payload region (record offsets are relative
    /// to this).
    pub book_payload_offset: u64,
}

/// A located payload record. `raw` is the stored bytes **as-is** — still
/// encrypted and/or compressed; the scheme layer applies the
/// decrypt-then-inflate pipeline.
#[derive(Debug, Clone, Copy)]
pub struct PayloadRecord<'a> {
    /// The record's own name tag (validated to equal the requested name).
    pub tag: &'a [u8],
    /// The record's real (non-negative) index.
    pub index: u64,
    /// True when the stored index was negative (record is Topaz-encrypted).
    pub encrypted: bool,
    /// True when `compressed_len > 0` (record is zlib-compressed).
    pub compressed: bool,
    /// The stored record bytes (undecoded).
    pub raw: &'a [u8],
}

/// The inline `metadata` record: an ordered map of key/value byte strings.
#[derive(Debug, Default, Clone)]
pub struct Metadata {
    /// Key/value entries, in the order they appear in the record.
    pub entries: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Metadata {
    /// Look up a metadata value by key.
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.entries.get(key).map(Vec::as_slice)
    }

    /// The comma-separated key names listed in the `keys` entry, or empty when
    /// absent/blank. These name the metadata values used for PID generation.
    pub fn keys(&self) -> Vec<&[u8]> {
        match self.entries.get(b"keys".as_slice()) {
            Some(v) if !v.is_empty() => v.split(|&b| b == b',').collect(),
            _ => Vec::new(),
        }
    }

    /// PID metadata `(md1, md2)` per `getPIDMetaInfo`: `md1` is the raw `keys`
    /// value (comma-separated names) and `md2` is the concatenation of the
    /// values those names reference.
    pub fn pid_meta(&self) -> (Vec<u8>, Vec<u8>) {
        let md1 = self
            .entries
            .get(b"keys".as_slice())
            .cloned()
            .unwrap_or_default();
        let mut md2 = Vec::new();
        for key in self.keys() {
            if let Some(value) = self.entries.get(key) {
                md2.extend_from_slice(value);
            }
        }
        (md1, md2)
    }
}

/// A forward/seek cursor over the container bytes that never panics: every read
/// is bounds-checked and reports [`FormatError::Truncated`] past the end.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }

    fn read_u8(&mut self) -> Result<u8> {
        let byte = *self
            .data
            .get(self.pos)
            .ok_or(FormatError::Truncated(self.pos))?;
        self.pos += 1;
        Ok(byte)
    }

    fn read_encoded(&mut self) -> Result<i64> {
        let rest = self
            .data
            .get(self.pos..)
            .ok_or(FormatError::Truncated(self.pos))?;
        let (value, consumed) = read_encoded_number(rest)?;
        self.pos += consumed;
        Ok(value)
    }

    /// Read an encoded-number length prefix, then that many raw bytes.
    fn read_lp_string(&mut self) -> Result<&'a [u8]> {
        let len = self.read_encoded()?;
        let len = usize::try_from(len)
            .map_err(|_| FormatError::Invalid(format!("negative string length {len}")))?;
        self.read_bytes(len)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(FormatError::Truncated(self.pos))?;
        let bytes = self
            .data
            .get(self.pos..end)
            .ok_or(FormatError::Truncated(self.pos))?;
        self.pos = end;
        Ok(bytes)
    }
}

/// Read a Topaz variable-length "encoded number" and return
/// `(value, bytes_consumed)`.
///
/// A leading `0xFF` byte is a negative-sign marker (not part of the magnitude).
/// A byte `< 0x80` is a single-byte value; otherwise the low 7 bits of each
/// byte accumulate big-endian (`acc = (acc << 7) + (b & 0x7F)`) while the high
/// bit is set. Reference: `docs/DEDRM_SCHEMES.md` §5.1.
pub fn read_encoded_number(data: &[u8]) -> Result<(i64, usize)> {
    let mut pos = 0usize;
    let mut byte = *data.get(pos).ok_or(FormatError::Truncated(pos))?;
    pos += 1;

    let negative = byte == 0xFF;
    if negative {
        byte = *data.get(pos).ok_or(FormatError::Truncated(pos))?;
        pos += 1;
    }

    let magnitude: i64 = if byte < 0x80 {
        i64::from(byte)
    } else {
        let mut acc = i64::from(byte & 0x7F);
        while byte >= 0x80 {
            byte = *data.get(pos).ok_or(FormatError::Truncated(pos))?;
            pos += 1;
            acc = (acc << 7) + i64::from(byte & 0x7F);
        }
        acc
    };

    Ok((if negative { -magnitude } else { magnitude }, pos))
}

impl TopazContainer {
    /// Parse a TPZ0 header into the named record table and `book_payload_offset`.
    ///
    /// Reference: `docs/DEDRM_SCHEMES.md` §5.2 / `parseTopazHeaders`.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let magic = data.get(0..4).ok_or(FormatError::Truncated(0))?;
        if magic != MAGIC {
            return Err(FormatError::BadMagic(
                String::from_utf8_lossy(magic).into_owned(),
            ));
        }

        let mut reader = Reader::new(data);
        reader.seek(4);

        let nb_records = reader.read_encoded()?;
        let nb_records = usize::try_from(nb_records).map_err(|_| {
            FormatError::Invalid(format!("negative header record count {nb_records}"))
        })?;

        let mut header_records: HashMap<Vec<u8>, Vec<RecordEntry>> = HashMap::new();
        for _ in 0..nb_records {
            let marker = reader.read_u8()?;
            if marker != HEADER_RECORD_MARKER {
                return Err(FormatError::Invalid(format!(
                    "expected header record marker 0x{HEADER_RECORD_MARKER:02x}, found 0x{marker:02x}"
                )));
            }
            let name = reader.read_lp_string()?.to_vec();

            let nb_values = reader.read_encoded()?;
            let nb_values = usize::try_from(nb_values).map_err(|_| {
                FormatError::Invalid(format!("negative header value count {nb_values}"))
            })?;

            let mut entries = Vec::with_capacity(nb_values);
            for _ in 0..nb_values {
                let offset = read_u64(reader.read_encoded()?, "record offset")?;
                let decompressed_len = read_u64(reader.read_encoded()?, "decompressed length")?;
                let compressed_len = read_u64(reader.read_encoded()?, "compressed length")?;
                entries.push(RecordEntry {
                    offset,
                    decompressed_len,
                    compressed_len,
                });
            }
            header_records.insert(name, entries);
        }

        let end = reader.read_u8()?;
        if end != END_OF_HEADERS_MARKER {
            return Err(FormatError::Invalid(format!(
                "expected end-of-headers marker 0x{END_OF_HEADERS_MARKER:02x}, found 0x{end:02x}"
            )));
        }

        Ok(Self {
            header_records,
            book_payload_offset: reader.pos as u64,
        })
    }

    /// Look up the `index`-th header entry for `name`.
    fn entry(&self, name: &[u8], index: usize) -> Result<&RecordEntry> {
        self.header_records
            .get(name)
            .and_then(|entries| entries.get(index))
            .ok_or_else(|| {
                FormatError::Invalid(format!(
                    "record {}[{index}] not found",
                    String::from_utf8_lossy(name)
                ))
            })
    }

    /// Locate the payload record `name[index]` and return its (undecoded) bytes
    /// plus its encrypted/compressed flags.
    ///
    /// The stored tag must match `name` and the decoded index must match
    /// `index` (a negative stored index marks the record encrypted, with real
    /// index `-stored - 1`). Reference: `docs/DEDRM_SCHEMES.md` §5.2 /
    /// `getBookPayloadRecord`.
    pub fn payload_record<'a>(
        &self,
        data: &'a [u8],
        name: &[u8],
        index: usize,
    ) -> Result<PayloadRecord<'a>> {
        let entry = *self.entry(name, index)?;
        let start = self
            .book_payload_offset
            .checked_add(entry.offset)
            .and_then(|abs| usize::try_from(abs).ok())
            .ok_or_else(|| FormatError::Invalid("payload record offset overflow".to_owned()))?;

        let mut reader = Reader::new(data);
        reader.seek(start);

        let tag = reader.read_lp_string()?;
        if tag != name {
            return Err(FormatError::Invalid(format!(
                "record tag {:?} does not match requested name {:?}",
                String::from_utf8_lossy(tag),
                String::from_utf8_lossy(name)
            )));
        }

        let stored_index = reader.read_encoded()?;
        let (encrypted, real_index) = if stored_index < 0 {
            (true, -stored_index - 1)
        } else {
            (false, stored_index)
        };
        if real_index != index as i64 {
            return Err(FormatError::Invalid(format!(
                "record index {real_index} does not match requested index {index}"
            )));
        }

        let compressed = entry.is_compressed();
        let stored_len = if compressed {
            entry.compressed_len
        } else {
            entry.decompressed_len
        };
        let stored_len = usize::try_from(stored_len)
            .map_err(|_| FormatError::Invalid(format!("record length {stored_len} too large")))?;
        let raw = reader.read_bytes(stored_len)?;

        Ok(PayloadRecord {
            tag,
            index: real_index as u64,
            encrypted,
            compressed,
            raw,
        })
    }

    /// Parse the inline (unencrypted) `metadata` record.
    ///
    /// Layout: tag `"metadata"`, a 1-byte flags field, a 1-byte record count,
    /// then that many `[key, value]` length-prefixed string pairs. Reference:
    /// `docs/DEDRM_SCHEMES.md` §5.2 / `parseMetadata`.
    pub fn parse_metadata(&self, data: &[u8]) -> Result<Metadata> {
        let entry = self.entry(b"metadata", 0)?;
        let start = self
            .book_payload_offset
            .checked_add(entry.offset)
            .and_then(|abs| usize::try_from(abs).ok())
            .ok_or_else(|| FormatError::Invalid("metadata offset overflow".to_owned()))?;

        let mut reader = Reader::new(data);
        reader.seek(start);

        let tag = reader.read_lp_string()?;
        if tag != b"metadata" {
            return Err(FormatError::Invalid(format!(
                "metadata tag mismatch: {:?}",
                String::from_utf8_lossy(tag)
            )));
        }

        let _flags = reader.read_u8()?;
        let count = reader.read_u8()?;

        let mut entries = BTreeMap::new();
        for _ in 0..count {
            let key = reader.read_lp_string()?.to_vec();
            let value = reader.read_lp_string()?.to_vec();
            entries.insert(key, value);
        }

        Ok(Metadata { entries })
    }
}

/// Convert a decoded encoded-number into a `u64`, rejecting negatives.
fn read_u64(value: i64, what: &str) -> Result<u64> {
    u64::try_from(value).map_err(|_| FormatError::Invalid(format!("negative {what} {value}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode an integer as a Topaz encoded-number (inverse of
    /// [`read_encoded_number`]).
    fn enc(n: i64) -> Vec<u8> {
        let mut out = Vec::new();
        if n < 0 {
            out.push(0xFF);
        }
        let magnitude = n.unsigned_abs();
        if magnitude < 0x80 {
            out.push(magnitude as u8);
            return out;
        }
        let mut groups = Vec::new();
        let mut v = magnitude;
        while v > 0 {
            groups.push((v & 0x7F) as u8);
            v >>= 7;
        }
        groups.reverse();
        // A positive number must not lead with 0xFF (the sign marker); when the
        // top group is 0x7F its continuation byte would be 0xFF, so prepend a
        // zero continuation group to disambiguate (the canonical container form).
        if n > 0 && groups[0] == 0x7F {
            groups.insert(0, 0x00);
        }
        let last = groups.len() - 1;
        for (i, g) in groups.iter().enumerate() {
            out.push(if i < last { g | 0x80 } else { *g });
        }
        out
    }

    /// Encode a length-prefixed string.
    fn lp(s: &[u8]) -> Vec<u8> {
        let mut out = enc(s.len() as i64);
        out.extend_from_slice(s);
        out
    }

    #[test]
    fn encoded_number_single_byte() {
        assert_eq!(read_encoded_number(&[0x05]).unwrap(), (5, 1));
        assert_eq!(read_encoded_number(&[0x00]).unwrap(), (0, 1));
        assert_eq!(read_encoded_number(&[0x7F]).unwrap(), (127, 1));
    }

    #[test]
    fn encoded_number_multi_byte() {
        // 300 = 0x12C -> groups [2, 44] -> [0x82, 0x2C].
        assert_eq!(read_encoded_number(&[0x82, 0x2C]).unwrap(), (300, 2));
        // 16384 = 0x4000 -> [0x81, 0x80, 0x00].
        assert_eq!(
            read_encoded_number(&[0x81, 0x80, 0x00]).unwrap(),
            (16384, 3)
        );
    }

    #[test]
    fn encoded_number_negative() {
        assert_eq!(read_encoded_number(&[0xFF, 0x05]).unwrap(), (-5, 2));
        assert_eq!(read_encoded_number(&[0xFF, 0x82, 0x2C]).unwrap(), (-300, 3));
    }

    #[test]
    fn encoded_number_roundtrips() {
        for n in [
            0i64, 1, 5, 127, 128, 300, 16383, 16384, 1_000_000, -1, -300, -70000,
        ] {
            let bytes = enc(n);
            assert_eq!(
                read_encoded_number(&bytes).unwrap(),
                (n, bytes.len()),
                "n={n}"
            );
        }
    }

    #[test]
    fn encoded_number_truncated() {
        assert!(matches!(
            read_encoded_number(&[]),
            Err(FormatError::Truncated(_))
        ));
        // High bit set but no continuation byte.
        assert!(matches!(
            read_encoded_number(&[0x82]),
            Err(FormatError::Truncated(_))
        ));
        // Negative marker with nothing after it.
        assert!(matches!(
            read_encoded_number(&[0xFF]),
            Err(FormatError::Truncated(_))
        ));
    }

    /// Build a synthetic TPZ0 container: a `metadata` record plus two `page`
    /// records — `page[0]` compressed (unencrypted) and `page[1]` encrypted
    /// (uncompressed).
    fn build_container() -> Vec<u8> {
        // --- payload records (offsets are relative to book_payload_offset) ---
        let mut metadata = Vec::new();
        metadata.extend_from_slice(&lp(b"metadata"));
        metadata.push(0x00); // flags
        metadata.push(0x03); // count
        metadata.extend_from_slice(&lp(b"keys"));
        metadata.extend_from_slice(&lp(b"key1,key2"));
        metadata.extend_from_slice(&lp(b"key1"));
        metadata.extend_from_slice(&lp(b"AAA"));
        metadata.extend_from_slice(&lp(b"key2"));
        metadata.extend_from_slice(&lp(b"BBB"));

        let comp_data = b"COMPRESSEDDATA";
        let mut page0 = Vec::new();
        page0.extend_from_slice(&lp(b"page"));
        page0.extend_from_slice(&enc(0)); // index 0, non-negative => not encrypted
        page0.extend_from_slice(comp_data);

        let enc_data = b"ENCRYPTEDDATA";
        let mut page1 = Vec::new();
        page1.extend_from_slice(&lp(b"page"));
        page1.extend_from_slice(&enc(-2)); // stored -2 => encrypted, real index 1
        page1.extend_from_slice(enc_data);

        let meta_off = 0u64;
        let page0_off = metadata.len() as u64;
        let page1_off = (metadata.len() + page0.len()) as u64;

        // --- header ---
        let mut header = Vec::new();
        header.extend_from_slice(&enc(2)); // two named records: "metadata", "page"

        header.push(HEADER_RECORD_MARKER);
        header.extend_from_slice(&lp(b"metadata"));
        header.extend_from_slice(&enc(1)); // one entry
        header.extend_from_slice(&enc(meta_off as i64));
        header.extend_from_slice(&enc(metadata.len() as i64)); // decompressed_len
        header.extend_from_slice(&enc(0)); // compressed_len 0 => uncompressed

        header.push(HEADER_RECORD_MARKER);
        header.extend_from_slice(&lp(b"page"));
        header.extend_from_slice(&enc(2)); // two entries
        header.extend_from_slice(&enc(page0_off as i64));
        header.extend_from_slice(&enc(999)); // decompressed_len (unused for compressed read)
        header.extend_from_slice(&enc(comp_data.len() as i64)); // compressed_len > 0
        header.extend_from_slice(&enc(page1_off as i64));
        header.extend_from_slice(&enc(enc_data.len() as i64)); // decompressed_len
        header.extend_from_slice(&enc(0)); // compressed_len 0 => uncompressed

        let mut file = Vec::new();
        file.extend_from_slice(MAGIC);
        file.extend_from_slice(&header);
        file.push(END_OF_HEADERS_MARKER);
        file.extend_from_slice(&metadata);
        file.extend_from_slice(&page0);
        file.extend_from_slice(&page1);
        file
    }

    #[test]
    fn parses_header_and_payload_offset() {
        let data = build_container();
        let container = TopazContainer::parse(&data).unwrap();

        assert_eq!(container.header_records.len(), 2);
        assert_eq!(container.header_records[b"metadata".as_slice()].len(), 1);
        assert_eq!(container.header_records[b"page".as_slice()].len(), 2);

        // The metadata record sits at the very start of the payload region.
        let meta_entry = container.header_records[b"metadata".as_slice()][0];
        assert_eq!(meta_entry.offset, 0);
        assert!(!meta_entry.is_compressed());

        // Sanity: the byte at book_payload_offset begins the metadata record,
        // whose first byte is the length prefix of "metadata" (== 8).
        assert_eq!(data[container.book_payload_offset as usize], 8);
    }

    #[test]
    fn compressed_and_encrypted_records() {
        let data = build_container();
        let container = TopazContainer::parse(&data).unwrap();

        let r0 = container.payload_record(&data, b"page", 0).unwrap();
        assert_eq!(r0.tag, b"page");
        assert_eq!(r0.index, 0);
        assert!(!r0.encrypted);
        assert!(r0.compressed);
        assert_eq!(r0.raw, b"COMPRESSEDDATA");

        let r1 = container.payload_record(&data, b"page", 1).unwrap();
        assert_eq!(r1.tag, b"page");
        assert_eq!(r1.index, 1);
        assert!(r1.encrypted);
        assert!(!r1.compressed);
        assert_eq!(r1.raw, b"ENCRYPTEDDATA");
    }

    #[test]
    fn parses_metadata_and_pid_info() {
        let data = build_container();
        let container = TopazContainer::parse(&data).unwrap();
        let meta = container.parse_metadata(&data).unwrap();

        assert_eq!(meta.get(b"key1"), Some(b"AAA".as_slice()));
        assert_eq!(meta.keys(), vec![b"key1".as_slice(), b"key2".as_slice()]);

        let (md1, md2) = meta.pid_meta();
        assert_eq!(md1, b"key1,key2");
        assert_eq!(md2, b"AAABBB");
    }

    #[test]
    fn rejects_bad_magic() {
        let mut data = build_container();
        data[0..4].copy_from_slice(b"XXXX");
        assert!(matches!(
            TopazContainer::parse(&data),
            Err(FormatError::BadMagic(_))
        ));
    }

    #[test]
    fn rejects_bad_header_marker() {
        let mut data = build_container();
        // Corrupt the first 0x63 header-record marker (right after enc(2) which
        // is one byte at offset 5).
        data[5] = 0x00;
        assert!(matches!(
            TopazContainer::parse(&data),
            Err(FormatError::Invalid(_))
        ));
    }

    #[test]
    fn missing_record_is_typed_error() {
        let data = build_container();
        let container = TopazContainer::parse(&data).unwrap();
        assert!(matches!(
            container.payload_record(&data, b"glyphs", 0),
            Err(FormatError::Invalid(_))
        ));
    }
}
