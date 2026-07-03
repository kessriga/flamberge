//! Palm Database (PDB) container parsing — the backbone of Mobipocket
//! (`.mobi/.azw/.prc`) and eReader (`.pdb`).
//!
//! All integers are big-endian. Layout: a 78-byte header (name, type/creator at
//! 0x3C, record count at 0x4C) followed by an array of 8-byte record-info
//! entries at offset 78. Reference: `docs/DEDRM_SCHEMES.md` §2.1 / §8.1.

use crate::{FormatError, Result};

const HEADER_LEN: usize = 78;
const NAME_LEN: usize = 32;
const TYPE_CREATOR_OFFSET: usize = 0x3C;
const NUM_RECORDS_OFFSET: usize = 0x4C;
const RECORD_ENTRY_LEN: usize = 8;

/// One record's location within the file.
#[derive(Debug, Clone, Copy)]
pub struct RecordInfo {
    /// Absolute file offset of this record's data.
    pub offset: u32,
    pub attributes: u8,
    /// 24-bit unique id.
    pub unique_id: u32,
}

/// A parsed Palm database: header fields plus the resolved record byte-ranges.
#[derive(Debug, Clone)]
pub struct PalmDb {
    /// Database name (offset 0x00, NUL-trimmed).
    pub name: Vec<u8>,
    /// 8-byte type+creator "magic" at offset 0x3C (e.g. `BOOKMOBI`, `PNRdPPrs`).
    pub type_creator: [u8; 8],
    pub records: Vec<RecordInfo>,
    total_len: usize,
}

impl PalmDb {
    /// Parse the header and record table from a full file image.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_LEN {
            return Err(FormatError::Truncated(HEADER_LEN));
        }

        let mut name = data[0..NAME_LEN].to_vec();
        if let Some(nul) = name.iter().position(|&b| b == 0) {
            name.truncate(nul);
        }

        let mut type_creator = [0u8; 8];
        type_creator.copy_from_slice(&data[TYPE_CREATOR_OFFSET..TYPE_CREATOR_OFFSET + 8]);

        let num_records =
            u16::from_be_bytes([data[NUM_RECORDS_OFFSET], data[NUM_RECORDS_OFFSET + 1]]) as usize;

        let table_end = HEADER_LEN + num_records * RECORD_ENTRY_LEN;
        if data.len() < table_end {
            return Err(FormatError::Truncated(table_end));
        }

        let mut records = Vec::with_capacity(num_records);
        for i in 0..num_records {
            let base = HEADER_LEN + i * RECORD_ENTRY_LEN;
            let offset = u32::from_be_bytes(data[base..base + 4].try_into().unwrap());
            let attributes = data[base + 4];
            let unique_id =
                (data[base + 5] as u32) << 16 | (data[base + 6] as u32) << 8 | data[base + 7] as u32;
            records.push(RecordInfo { offset, attributes, unique_id });
        }

        Ok(PalmDb { name, type_creator, records, total_len: data.len() })
    }

    /// Byte range `[start, end)` of record `index` within the file image.
    pub fn record_range(&self, index: usize) -> Option<(usize, usize)> {
        let start = self.records.get(index)?.offset as usize;
        let end = self
            .records
            .get(index + 1)
            .map(|r| r.offset as usize)
            .unwrap_or(self.total_len);
        Some((start, end))
    }

    /// Slice of record `index` from the original `data` image.
    pub fn record<'a>(&self, data: &'a [u8], index: usize) -> Option<&'a [u8]> {
        let (start, end) = self.record_range(index)?;
        data.get(start..end)
    }

    pub fn num_records(&self) -> usize {
        self.records.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal 2-record PDB image for a round-trip parse.
    fn synth() -> Vec<u8> {
        let mut d = vec![0u8; HEADER_LEN + 2 * RECORD_ENTRY_LEN + 8];
        d[..4].copy_from_slice(b"Test");
        d[TYPE_CREATOR_OFFSET..TYPE_CREATOR_OFFSET + 8].copy_from_slice(b"BOOKMOBI");
        d[NUM_RECORDS_OFFSET..NUM_RECORDS_OFFSET + 2].copy_from_slice(&2u16.to_be_bytes());
        let rec0 = (HEADER_LEN + 2 * RECORD_ENTRY_LEN) as u32;
        let rec1 = rec0 + 4;
        d[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&rec0.to_be_bytes());
        d[HEADER_LEN + 8..HEADER_LEN + 12].copy_from_slice(&rec1.to_be_bytes());
        d
    }

    #[test]
    fn parses_header_and_records() {
        let img = synth();
        let db = PalmDb::parse(&img).unwrap();
        assert_eq!(db.name, b"Test");
        assert_eq!(&db.type_creator, b"BOOKMOBI");
        assert_eq!(db.num_records(), 2);
        assert_eq!(db.record(&img, 0).unwrap().len(), 4);
    }
}
