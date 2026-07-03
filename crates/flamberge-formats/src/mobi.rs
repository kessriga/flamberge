//! MOBI / PalmDoc / EXTH header parsing (Mobipocket `.mobi/.azw/.prc`).
//!
//! Parses record 0 of a Palm database into the fields the Mobipocket DRM logic
//! needs — no decryption happens here. All integers are big-endian. The
//! `BOOKMOBI` layout carries a full MOBI header + optional EXTH block; the older
//! `TEXtREAd` layout only has the three PalmDoc fields.
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §2.2. Original: `mobidedrm.py`
//! (`MobiBook.__init__`, `getPIDMetaInfo`).

use std::collections::BTreeMap;

use crate::palmdb::PalmDb;
use crate::{FormatError, Result};

/// PalmDoc compression value for HUFF/CDIC records. When set, the multibyte
/// trailing entry is *not* part of the encrypted region.
pub const COMPRESSION_HUFF_CDIC: u16 = 17480; // 0x4448

/// The DRM voucher block located at record-0 offset 0xA8 (four big-endian u32s).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DrmBlock {
    /// Offset (within record 0) of the DRM voucher array.
    pub ptr: u32,
    /// Number of 48-byte voucher entries.
    pub count: u32,
    /// Total byte size of the voucher array.
    pub size: u32,
    pub flags: u32,
}

/// Parsed record-0 header for a Mobipocket book.
#[derive(Debug, Clone)]
pub struct MobiHeader {
    /// PalmDoc compression: 1 = none, 2 = PalmDoc, [`COMPRESSION_HUFF_CDIC`] = HUFF/CDIC.
    pub compression: u16,
    /// Number of text records (records `1..=text_record_count`).
    pub text_record_count: u16,
    /// Encryption type: 0 = none, 1 = old Mobipocket, 2 = Mobipocket PID.
    pub encryption_type: u16,
    /// True for the older `TEXtREAd` layout (no MOBI header / EXTH).
    pub is_textread: bool,
    /// MOBI header length (0 for `TEXtREAd`).
    pub mobi_length: u32,
    /// MOBI format version.
    pub mobi_version: u32,
    /// Text codepage (e.g. 1252 or 65001).
    pub codepage: u32,
    /// Raw EXTH flags field (bit 0x40 = EXTH present).
    pub exth_flag: u32,
    /// The DRM voucher block (all-zero when absent).
    pub drm: DrmBlock,
    /// Trailing-data flags, already adjusted: only populated when
    /// `mobi_length >= 0xE4 && mobi_version >= 5`, with the low bit cleared
    /// unless compression is HUFF/CDIC.
    pub extra_data_flags: u16,
    /// EXTH records, keyed by record type. Notable types: 209 (PID metadata),
    /// 503 (title), 406 (rental expiry).
    pub exth: BTreeMap<u32, Vec<u8>>,
}

fn be_u16(data: &[u8], off: usize) -> Result<u16> {
    data.get(off..off + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .ok_or(FormatError::Truncated(off + 2))
}

fn be_u32(data: &[u8], off: usize) -> Result<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or(FormatError::Truncated(off + 4))
}

impl MobiHeader {
    /// Parse record 0. `type_creator` is the PalmDB magic at file offset 0x3C;
    /// only `BOOKMOBI` and `TEXtREAd` are accepted.
    pub fn parse(record0: &[u8], type_creator: &[u8; 8]) -> Result<MobiHeader> {
        let is_textread = match type_creator {
            b"BOOKMOBI" => false,
            b"TEXtREAd" => true,
            other => {
                return Err(FormatError::BadMagic(
                    String::from_utf8_lossy(other).into_owned(),
                ))
            }
        };

        // PalmDoc header — present in both layouts.
        let compression = be_u16(record0, 0x00)?;
        let text_record_count = be_u16(record0, 0x08)?;
        let encryption_type = be_u16(record0, 0x0C)?;

        let mut header = MobiHeader {
            compression,
            text_record_count,
            encryption_type,
            is_textread,
            mobi_length: 0,
            mobi_version: 0,
            codepage: 0,
            exth_flag: 0,
            drm: DrmBlock::default(),
            extra_data_flags: 0,
            exth: BTreeMap::new(),
        };

        // TEXtREAd has no MOBI header; the caller reads the book key elsewhere.
        if is_textread {
            return Ok(header);
        }

        header.mobi_length = be_u32(record0, 0x14)?;
        header.codepage = be_u32(record0, 0x1C)?;
        header.mobi_version = be_u32(record0, 0x68)?;
        header.exth_flag = be_u32(record0, 0x80)?;

        // DRM voucher block at 0xA8 (present when the record is long enough).
        if record0.len() >= 0xB8 {
            header.drm = DrmBlock {
                ptr: be_u32(record0, 0xA8)?,
                count: be_u32(record0, 0xAC)?,
                size: be_u32(record0, 0xB0)?,
                flags: be_u32(record0, 0xB4)?,
            };
        }

        // extra_data_flags only exist for MOBI length >= 0xE4 and version >= 5.
        if header.mobi_length >= 0xE4 && header.mobi_version >= 5 {
            let mut flags = be_u16(record0, 0xF2)?;
            // For non-HUFF/CDIC, the multibyte trailing entry is inside the
            // encrypted region, so clear its bit.
            if header.compression != COMPRESSION_HUFF_CDIC {
                flags &= 0xFFFE;
            }
            header.extra_data_flags = flags;
        }

        // EXTH block at 16 + mobi_length when the flag bit is set.
        if header.exth_flag & 0x40 != 0 {
            let start = 16usize.saturating_add(header.mobi_length as usize);
            if let Some(exth) = record0.get(start..) {
                header.exth = parse_exth(exth)?;
            }
        }

        Ok(header)
    }

    /// Convenience: parse a full file image (runs [`PalmDb::parse`] first).
    pub fn from_image(data: &[u8]) -> Result<MobiHeader> {
        let db = PalmDb::parse(data)?;
        let record0 = db
            .record(data, 0)
            .ok_or_else(|| FormatError::Invalid("missing record 0".into()))?;
        MobiHeader::parse(record0, &db.type_creator)
    }

    /// Recover the book's display title (`mobidedrm.py::getBookTitle`).
    ///
    /// Three-tier fallback: EXTH record 503, else the MOBI "full name" field (a
    /// `>II` offset/length pair at record-0 offset 0x54 pointing back into
    /// `record0`), else the PalmDB name (`db_name`, NUL-terminated, up to 32
    /// bytes). `record0` is the raw record-0 bytes; `db_name` is the file's
    /// first 32 bytes. Codepage 65001 decodes as UTF-8 (lossy); anything else is
    /// treated as Latin-1 (a superset of ASCII — high bytes are approximate, but
    /// filename cleanup drops non-ASCII regardless). Reference: §2.6.
    pub fn book_title(&self, record0: &[u8], db_name: &[u8]) -> String {
        let mut title: &[u8] = b"";
        if !self.is_textread {
            if let Some(exth503) = self.exth.get(&503) {
                title = exth503;
            } else if let (Ok(toff), Ok(tlen)) = (be_u32(record0, 0x54), be_u32(record0, 0x58)) {
                let (start, end) = (toff as usize, toff as usize + tlen as usize);
                if let Some(slice) = record0.get(start..end) {
                    title = slice;
                }
            }
        }
        if title.is_empty() {
            // PalmDB name: NUL-terminated, at most 32 bytes.
            let name = &db_name[..db_name.len().min(32)];
            title = match name.iter().position(|&b| b == 0) {
                Some(nul) => &name[..nul],
                None => name,
            };
        }
        decode_title(title, self.codepage)
    }

    /// Reconstruct the PID metadata `(rec209, token)` per `getPIDMetaInfo`.
    ///
    /// `rec209` is EXTH record 209; `token` is the concatenation of the EXTH
    /// records it references — walk `rec209` in 5-byte groups of
    /// `[tag: u8][key: big-endian u32]` and append `exth[key]` for each.
    pub fn pid_meta(&self) -> (Vec<u8>, Vec<u8>) {
        let rec209 = self.exth.get(&209).cloned().unwrap_or_default();
        let mut token = Vec::new();
        let mut i = 0;
        while i + 5 <= rec209.len() {
            let key =
                u32::from_be_bytes([rec209[i + 1], rec209[i + 2], rec209[i + 3], rec209[i + 4]]);
            if let Some(value) = self.exth.get(&key) {
                token.extend_from_slice(value);
            }
            i += 5;
        }
        (rec209, token)
    }
}

/// Decode title bytes to a `String`. Codepage 65001 is UTF-8 (decoded lossily);
/// every other codepage is treated as Latin-1 (each byte is its own code point).
fn decode_title(bytes: &[u8], codepage: u32) -> String {
    if codepage == 65001 {
        String::from_utf8_lossy(bytes).into_owned()
    } else {
        bytes.iter().map(|&b| b as char).collect()
    }
}

/// Parse an EXTH block: `"EXTH"`, header length (u32), item count (u32), then
/// records of `[type: u32][size: u32 incl. 8-byte header][content: size-8]`.
fn parse_exth(exth: &[u8]) -> Result<BTreeMap<u32, Vec<u8>>> {
    let mut map = BTreeMap::new();
    if exth.len() < 12 || &exth[0..4] != b"EXTH" {
        // No/short EXTH is not fatal — the book may simply lack metadata.
        return Ok(map);
    }
    let nitems = be_u32(exth, 8)?;
    let mut pos = 12usize;
    for _ in 0..nitems {
        let rtype = be_u32(exth, pos)?;
        let size = be_u32(exth, pos + 4)? as usize;
        // `size` includes the 8-byte header; guard against malformed lengths.
        if size < 8 || pos + size > exth.len() {
            return Err(FormatError::Invalid("EXTH record overruns block".into()));
        }
        map.insert(rtype, exth[pos + 8..pos + size].to_vec());
        pos += size;
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an EXTH block from `(type, content)` pairs.
    fn build_exth(items: &[(u32, &[u8])]) -> Vec<u8> {
        let mut records = Vec::new();
        for (rtype, content) in items {
            let size = 8 + content.len();
            records.extend_from_slice(&rtype.to_be_bytes());
            records.extend_from_slice(&(size as u32).to_be_bytes());
            records.extend_from_slice(content);
        }
        let mut exth = Vec::new();
        exth.extend_from_slice(b"EXTH");
        exth.extend_from_slice(&((12 + records.len()) as u32).to_be_bytes());
        exth.extend_from_slice(&(items.len() as u32).to_be_bytes());
        exth.extend_from_slice(&records);
        exth
    }

    /// Synthesize a BOOKMOBI record 0 with a MOBI header and EXTH block.
    fn build_record0(compression: u16, mobi_version: u32, exth: &[u8]) -> Vec<u8> {
        let mobi_length: u32 = 0xE4;
        // Record 0 = 16-byte PalmDoc header + mobi_length header + EXTH.
        let mut r = vec![0u8; 16 + mobi_length as usize];
        r[0x00..0x02].copy_from_slice(&compression.to_be_bytes());
        r[0x08..0x0A].copy_from_slice(&7u16.to_be_bytes()); // text record count
        r[0x0C..0x0E].copy_from_slice(&2u16.to_be_bytes()); // encryption type 2
        r[0x10..0x14].copy_from_slice(b"MOBI");
        r[0x14..0x18].copy_from_slice(&mobi_length.to_be_bytes());
        r[0x1C..0x20].copy_from_slice(&65001u32.to_be_bytes()); // codepage
        r[0x68..0x6C].copy_from_slice(&mobi_version.to_be_bytes());
        r[0x80..0x84].copy_from_slice(&0x40u32.to_be_bytes()); // EXTH present
                                                               // DRM block at 0xA8.
        r[0xA8..0xAC].copy_from_slice(&0x0400u32.to_be_bytes()); // ptr
        r[0xAC..0xB0].copy_from_slice(&1u32.to_be_bytes()); // count
        r[0xB0..0xB4].copy_from_slice(&0x30u32.to_be_bytes()); // size
        r[0xB4..0xB8].copy_from_slice(&0u32.to_be_bytes()); // flags
        r[0xF2..0xF4].copy_from_slice(&0x0003u16.to_be_bytes()); // extra_data_flags
        r.extend_from_slice(exth);
        r
    }

    #[test]
    fn parses_bookmobi_record0_and_exth() {
        // rec209 references EXTH record 300; token should be that record's bytes.
        let mut rec209 = vec![0u8]; // tag byte
        rec209.extend_from_slice(&300u32.to_be_bytes());
        let exth = build_exth(&[(209, &rec209), (300, b"TOKEN"), (503, b"Title")]);
        let record0 = build_record0(2, 6, &exth);

        let h = MobiHeader::parse(&record0, b"BOOKMOBI").unwrap();
        assert_eq!(h.compression, 2);
        assert_eq!(h.text_record_count, 7);
        assert_eq!(h.encryption_type, 2);
        assert!(!h.is_textread);
        assert_eq!(h.mobi_length, 0xE4);
        assert_eq!(h.mobi_version, 6);
        assert_eq!(h.codepage, 65001);
        assert_eq!(h.exth_flag & 0x40, 0x40);
        assert_eq!(
            h.drm,
            DrmBlock {
                ptr: 0x0400,
                count: 1,
                size: 0x30,
                flags: 0
            }
        );
        // PalmDoc compression => low bit of extra_data_flags cleared (3 -> 2).
        assert_eq!(h.extra_data_flags, 0x0002);
        assert_eq!(
            h.exth.get(&503).map(|v| v.as_slice()),
            Some(b"Title".as_slice())
        );

        let (rec, token) = h.pid_meta();
        assert_eq!(rec, rec209);
        assert_eq!(token, b"TOKEN");
    }

    #[test]
    fn huff_cdic_keeps_low_bit() {
        let exth = build_exth(&[(300, b"x")]);
        let record0 = build_record0(COMPRESSION_HUFF_CDIC, 6, &exth);
        let h = MobiHeader::parse(&record0, b"BOOKMOBI").unwrap();
        // HUFF/CDIC => low bit preserved (3 stays 3).
        assert_eq!(h.extra_data_flags, 0x0003);
    }

    #[test]
    fn textread_stops_after_palmdoc_fields() {
        let mut r = vec![0u8; 16];
        r[0x00..0x02].copy_from_slice(&1u16.to_be_bytes());
        r[0x08..0x0A].copy_from_slice(&3u16.to_be_bytes());
        r[0x0C..0x0E].copy_from_slice(&0u16.to_be_bytes());
        let h = MobiHeader::parse(&r, b"TEXtREAd").unwrap();
        assert!(h.is_textread);
        assert_eq!(h.text_record_count, 3);
        assert_eq!(h.mobi_length, 0);
        assert!(h.exth.is_empty());
    }

    #[test]
    fn book_title_prefers_exth_503() {
        let exth = build_exth(&[(503, b"The Real Title")]);
        let record0 = build_record0(2, 6, &exth);
        let h = MobiHeader::parse(&record0, b"BOOKMOBI").unwrap();
        // db_name is ignored when EXTH 503 is present.
        assert_eq!(h.book_title(&record0, b"PALMNAME\0"), "The Real Title");
    }

    #[test]
    fn book_title_falls_back_to_full_name_offset() {
        // No EXTH 503: read the >II full-name pointer at 0x54 into record 0.
        let title = b"Full Name Field";
        let exth = build_exth(&[(300, b"x")]); // some other EXTH, no 503
        let mut record0 = build_record0(2, 6, &exth);
        let toff = record0.len() as u32;
        record0.extend_from_slice(title);
        record0[0x54..0x58].copy_from_slice(&toff.to_be_bytes());
        record0[0x58..0x5c].copy_from_slice(&(title.len() as u32).to_be_bytes());
        let h = MobiHeader::parse(&record0, b"BOOKMOBI").unwrap();
        assert_eq!(h.book_title(&record0, b"PALMNAME\0"), "Full Name Field");
    }

    #[test]
    fn book_title_falls_back_to_db_name() {
        // TEXtREAd has no MOBI header, so the title comes from the PalmDB name.
        let mut r = vec![0u8; 16];
        r[0x0C..0x0E].copy_from_slice(&0u16.to_be_bytes());
        let h = MobiHeader::parse(&r, b"TEXtREAd").unwrap();
        let mut db_name = b"My Palm Book".to_vec();
        db_name.resize(32, 0); // NUL-padded 32-byte name field
        assert_eq!(h.book_title(&r, &db_name), "My Palm Book");
    }

    #[test]
    fn book_title_utf8_codepage() {
        // Codepage 65001 → UTF-8 decoding of multibyte content.
        let exth = build_exth(&[(503, "Café ☕".as_bytes())]);
        let record0 = build_record0(2, 6, &exth); // codepage 65001
        let h = MobiHeader::parse(&record0, b"BOOKMOBI").unwrap();
        assert_eq!(h.book_title(&record0, b""), "Café ☕");
    }

    #[test]
    fn rejects_bad_magic() {
        let r = vec![0u8; 16];
        assert!(matches!(
            MobiHeader::parse(&r, b"DUMMY\0\0\0"),
            Err(FormatError::BadMagic(_))
        ));
    }
}
