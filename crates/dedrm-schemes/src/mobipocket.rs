//! Mobipocket (MOBI/AZW/PRC) DRM removal.
//!
//! Flow (§2): parse PalmDB → read record-0 crypto type → for each candidate PID
//! derive `temp_key = PC1(keyvec1, pid.pad16, encrypt)`, match voucher checksum,
//! `PC1(temp_key, cookie)` → `finalkey` → PC1-decrypt text records `1..=records`
//! (stripping trailing-data bytes). Reference: `docs/DEDRM_SCHEMES.md` §2.
//!
//! Original: `mobidedrm.py` (`MobiBook.processBook`, `parseDRM`,
//! `getSizeOfTrailingDataEntries`) and `kgenpids.py` (`getKindlePids`).

use crate::{DecryptedBook, KeyStore, Result, SchemeError};
use dedrm_crypto::pc1;
use dedrm_formats::mobi::MobiHeader;
use dedrm_formats::palmdb::PalmDb;
use dedrm_keys::pid;

/// PC1 master key for type-2 PID key derivation and the default fallback.
pub const KEYVEC1: [u8; 16] = [
    0x72, 0x38, 0x33, 0xB0, 0xB4, 0xF2, 0xE3, 0xCA, 0xDF, 0x09, 0x01, 0xD6, 0xE2, 0xE0, 0x3F, 0x96,
];
/// Type-1 (old Mobipocket) fixed book-key vector.
pub const T1_KEYVEC: &[u8; 16] = b"QDCVEPMU675RUBSZ";

/// Size in bytes of one DRM voucher entry (`struct '>LLLBxxx32s'`).
const VOUCHER_LEN: usize = 0x30;

/// True if this looks like a Mobipocket PalmDB (`BOOKMOBI` / `TEXtREAd`).
pub fn detect(data: &[u8]) -> bool {
    PalmDb::parse(data)
        .map(|db| &db.type_creator == b"BOOKMOBI" || &db.type_creator == b"TEXtREAd")
        .unwrap_or(false)
}

fn be_u32(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// `getSizeOfTrailingDataEntries` (§2.4): number of trailing bytes appended to a
/// text record that are *not* part of the encrypted region. `flags` is the
/// already-adjusted `extra_data_flags`.
fn trailing_data_size(data: &[u8], flags: u16) -> usize {
    // One backward base-128 varint (7 bits/byte, MSB terminates or bitpos>=28).
    fn entry_size(data: &[u8], mut size: usize) -> usize {
        let mut bitpos = 0usize;
        let mut result = 0usize;
        while size > 0 {
            let v = data[size - 1] as usize;
            result |= (v & 0x7F) << bitpos;
            bitpos += 7;
            size -= 1;
            if (v & 0x80) != 0 || bitpos >= 28 || size == 0 {
                break;
            }
        }
        result
    }

    let mut num = 0usize;
    let mut testflags = flags >> 1;
    while testflags != 0 {
        if testflags & 1 != 0 {
            // Guard against a malformed record claiming more trailing bytes than
            // it has, which would otherwise underflow the slice length.
            num += entry_size(data, data.len().saturating_sub(num));
        }
        testflags >>= 1;
    }
    // Low bit: a multibyte-overlap entry whose length is in its final 2 bits.
    if flags & 1 != 0 {
        if let Some(idx) = data.len().checked_sub(num + 1) {
            num += (data[idx] as usize & 0x3) + 1;
        }
    }
    num.min(data.len())
}

/// Scan `vouchers` (`count` × 48-byte entries) for a book key that unwraps under
/// `temp_key`. When `require_flags`, the recovered `flags & 0x1F` must equal 1
/// (the per-PID path); the PID-less fallback drops that check. `§2.3`.
fn scan_vouchers(
    vouchers: &[u8],
    count: usize,
    temp_key: &[u8],
    require_flags: bool,
) -> Result<Option<[u8; 16]>> {
    let key_sum = (temp_key.iter().map(|&b| b as u32).sum::<u32>() & 0xFF) as u8;
    for i in 0..count {
        let base = i * VOUCHER_LEN;
        let Some(entry) = vouchers.get(base..base + VOUCHER_LEN) else {
            break;
        };
        // '>LLLBxxx32s': verification, size, type, cksum, 3 pad, cookie(32).
        let verification = u32::from_be_bytes([entry[0], entry[1], entry[2], entry[3]]);
        let cksum = entry[12];
        if cksum != key_sum {
            continue;
        }
        let cookie = pc1::decrypt(temp_key, &entry[16..48])?;
        // '>LL16sLL': ver, flags, finalkey(16), expiry, expiry2.
        let Some(ver) = be_u32(&cookie, 0) else { continue };
        let Some(flags) = be_u32(&cookie, 4) else {
            continue;
        };
        if verification == ver && (!require_flags || flags & 0x1F == 1) {
            let mut finalkey = [0u8; 16];
            finalkey.copy_from_slice(&cookie[8..24]);
            return Ok(Some(finalkey));
        }
    }
    Ok(None)
}

/// Recover the type-2 book key by trying each candidate PID, then the PID-less
/// fallback (`temp_key = keyvec1`). `pids` must be 8-char PIDs.
fn find_book_key(vouchers: &[u8], count: usize, pids: &[String]) -> Result<Option<[u8; 16]>> {
    for p in pids {
        // bigpid = pid.ljust(16, b'\0'); temp_key = PC1(keyvec1, bigpid, encrypt).
        let mut bigpid = p.as_bytes().to_vec();
        bigpid.resize(16, 0);
        let temp_key = pc1::encrypt(&KEYVEC1, &bigpid)?;
        if let Some(key) = scan_vouchers(vouchers, count, &temp_key, true)? {
            return Ok(Some(key));
        }
    }
    // Fallback: default encoding, no PID, only require verification == ver.
    scan_vouchers(vouchers, count, &KEYVEC1, false)
}

/// Normalize candidate PIDs to the 8-char form the matcher uses (§2.5): 10-char
/// PIDs are truncated to their first 8 chars; 8-char PIDs pass through; anything
/// else is dropped.
fn normalize_pids(header: &MobiHeader, keys: &KeyStore) -> Vec<String> {
    let (rec209, token) = header.pid_meta();
    let mut raw: Vec<String> = keys.pids.clone();
    for serial in &keys.serials {
        raw.push(pid::book_pid_from_serial(serial.as_bytes(), &rec209, &token));
        raw.push(pid::eink_pid_from_serial(serial));
    }

    let mut good = Vec::with_capacity(raw.len());
    for p in raw {
        match p.len() {
            10 => good.push(p[..8].to_string()),
            8 => good.push(p),
            _ => {} // wrong length — ignore
        }
    }
    good
}

/// Output file extension (no dot) for a decrypted book (`getBookExtension`).
fn book_extension(print_replica: bool, mobi_version: u32) -> String {
    if print_replica {
        "azw4"
    } else if mobi_version >= 8 {
        "azw3"
    } else {
        "mobi"
    }
    .to_string()
}

/// Remove Mobipocket DRM from a full `.mobi/.azw/.prc` file image.
pub fn decrypt(input: &[u8], keys: &KeyStore) -> Result<DecryptedBook> {
    // Fall through to the next Kindle-family scheme if this isn't a Mobi PalmDB.
    if !detect(input) {
        return Err(SchemeError::NotThisScheme);
    }

    let db = PalmDb::parse(input)?;
    let header = MobiHeader::from_image(input)?;
    let (rec0_start, _) = db
        .record_range(0)
        .ok_or(SchemeError::NotThisScheme)?;

    // Recover the display title for output naming (§2.6). record 0 slice plus the
    // 32-byte PalmDB name at the head of the file.
    let title = db
        .record(input, 0)
        .map(|rec0| header.book_title(rec0, input));

    // Unencrypted: pass the file through untouched, still detecting Print Replica.
    if header.encryption_type == 0 {
        let print_replica = db
            .record(input, 1)
            .map(|r| r.starts_with(b"%MOP"))
            .unwrap_or(false);
        return Ok(DecryptedBook {
            data: input.to_vec(),
            extension: book_extension(print_replica, header.mobi_version),
            title,
        });
    }
    if header.encryption_type != 1 && header.encryption_type != 2 {
        return Err(SchemeError::UnknownEncryption(header.encryption_type));
    }

    // Library/rental books (EXTH 406, big-endian u64) cannot be decoded.
    if let Some(v406) = header.exth.get(&406) {
        if v406.len() >= 8 && v406[..8].iter().any(|&b| b != 0) {
            return Err(SchemeError::RentalBook);
        }
    }

    // Record 0 within the file image, used for type-1 book-key extraction.
    let record0 = db
        .record(input, 0)
        .ok_or(SchemeError::NotThisScheme)?;

    let found_key: [u8; 16] = if header.encryption_type == 1 {
        // §2.3 type 1: fixed key vector over the stored book key.
        let off = if header.is_textread {
            0x0E
        } else {
            header.mobi_length as usize + 16
        };
        let bookkey_data = record0
            .get(off..off + 16)
            .ok_or_else(|| SchemeError::Format(dedrm_formats::FormatError::Truncated(off + 16)))?;
        let key = pc1::decrypt(T1_KEYVEC, bookkey_data)?;
        key.try_into()
            .map_err(|_| SchemeError::NoKeyWorked)?
    } else {
        // §2.3 type 2: voucher matching over candidate PIDs.
        if header.drm.count == 0 {
            return Err(SchemeError::DrmNotInitialised);
        }
        let ptr = header.drm.ptr as usize;
        let size = header.drm.size as usize;
        let vouchers = record0
            .get(ptr..ptr + size)
            .ok_or_else(|| SchemeError::Format(dedrm_formats::FormatError::Truncated(ptr + size)))?;
        let goodpids = normalize_pids(&header, keys);
        find_book_key(vouchers, header.drm.count as usize, &goodpids)?
            .ok_or(SchemeError::NoKeyWorked)?
    };

    // Build the output as an in-place edit of the file: record lengths are
    // preserved (trailing bytes re-appended verbatim), so every record offset in
    // the PalmDB table stays valid.
    let mut out = input.to_vec();
    let records = header.text_record_count as usize;
    let mut print_replica = false;

    for i in 1..=records {
        let (start, end) = db.record_range(i).ok_or_else(|| {
            SchemeError::Format(dedrm_formats::FormatError::Invalid(format!(
                "text record {i} missing from record table"
            )))
        })?;
        let record = &input[start..end];
        let extra = trailing_data_size(record, header.extra_data_flags);
        let body_len = record.len() - extra;
        let decoded = pc1::decrypt(&found_key, &record[..body_len])?;
        if i == 1 {
            print_replica = decoded.starts_with(b"%MOP");
        }
        out[start..start + decoded.len()].copy_from_slice(&decoded);
    }

    // Patch record 0 so the output is a clean, DRM-free book (§2.4 / processBook).
    if header.encryption_type == 2 {
        // Zero the DRM voucher block.
        let ptr = rec0_start + header.drm.ptr as usize;
        let size = header.drm.size as usize;
        if let Some(block) = out.get_mut(ptr..ptr + size) {
            block.fill(0);
        }
        // Kill the DRM pointers at 0xA8: drm_ptr = 0xFFFFFFFF, rest zeroed.
        if let Some(block) = out.get_mut(rec0_start + 0xA8..rec0_start + 0xA8 + 16) {
            block.fill(0);
            block[..4].fill(0xFF);
        }
    }
    // Clear the encryption type at 0x0C (both type 1 and 2).
    if let Some(block) = out.get_mut(rec0_start + 0x0C..rec0_start + 0x0E) {
        block.fill(0);
    }

    Ok(DecryptedBook {
        data: out,
        extension: book_extension(print_replica, header.mobi_version),
        title,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dedrm_formats::mobi::COMPRESSION_HUFF_CDIC;

    // ---- trailing-data varint ------------------------------------------------

    #[test]
    fn trailing_size_multibyte_only() {
        // flags & 1 set, flags>>1 == 0: only the multibyte-overlap entry.
        // last byte & 3 == 2 → size 3.
        let data = [0u8, 0u8, 0b0000_0010u8];
        assert_eq!(trailing_data_size(&data, 0x01), 3);
    }

    #[test]
    fn trailing_size_single_varint() {
        // flags == 0b10 → one varint entry, no multibyte. A terminating byte with
        // MSB set encodes its low 7 bits as the length (here 5).
        let data = [0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0x85u8];
        assert_eq!(trailing_data_size(&data, 0x02), 5);
    }

    #[test]
    fn trailing_size_none() {
        assert_eq!(trailing_data_size(&[1, 2, 3, 4], 0), 0);
    }

    // ---- voucher matching ----------------------------------------------------

    /// Build a 48-byte voucher whose cookie decrypts (under `temp_key`) to
    /// `(ver, flags, finalkey, 0, 0)`, and whose `verification` field is `ver`.
    fn make_voucher(temp_key: &[u8], ver: u32, flags: u32, finalkey: &[u8; 16]) -> Vec<u8> {
        let mut cookie_plain = Vec::new();
        cookie_plain.extend_from_slice(&ver.to_be_bytes());
        cookie_plain.extend_from_slice(&flags.to_be_bytes());
        cookie_plain.extend_from_slice(finalkey);
        cookie_plain.extend_from_slice(&0u32.to_be_bytes()); // expiry
        cookie_plain.extend_from_slice(&0u32.to_be_bytes()); // expiry2
        let cookie_enc = pc1::encrypt(temp_key, &cookie_plain).unwrap();
        let key_sum = (temp_key.iter().map(|&b| b as u32).sum::<u32>() & 0xFF) as u8;

        let mut v = Vec::with_capacity(VOUCHER_LEN);
        v.extend_from_slice(&ver.to_be_bytes()); // verification
        v.extend_from_slice(&0u32.to_be_bytes()); // size
        v.extend_from_slice(&0u32.to_be_bytes()); // type
        v.push(key_sum); // cksum
        v.extend_from_slice(&[0, 0, 0]); // pad
        v.extend_from_slice(&cookie_enc); // cookie(32)
        assert_eq!(v.len(), VOUCHER_LEN);
        v
    }

    #[test]
    fn voucher_matches_pid() {
        let pid = "12345678";
        let mut bigpid = pid.as_bytes().to_vec();
        bigpid.resize(16, 0);
        let temp_key = pc1::encrypt(&KEYVEC1, &bigpid).unwrap();
        let finalkey = *b"0123456789abcdef";
        let voucher = make_voucher(&temp_key, 0xDEAD_BEEF, 0x01, &finalkey);

        let got = find_book_key(&voucher, 1, &[pid.to_string()]).unwrap();
        assert_eq!(got, Some(finalkey));
    }

    #[test]
    fn voucher_rejects_wrong_flags_then_falls_back() {
        // A voucher keyed to the PID but with flags&0x1F != 1 is rejected by the
        // per-PID path; a second voucher keyed to KEYVEC1 is caught by fallback.
        let pid = "12345678";
        let mut bigpid = pid.as_bytes().to_vec();
        bigpid.resize(16, 0);
        let temp_key = pc1::encrypt(&KEYVEC1, &bigpid).unwrap();

        let pid_final = *b"AAAAAAAAAAAAAAAA";
        let bad = make_voucher(&temp_key, 0x11, 0x00, &pid_final); // flags 0 → rejected
        let fallback_final = *b"BBBBBBBBBBBBBBBB";
        let good = make_voucher(&KEYVEC1, 0x22, 0x00, &fallback_final);

        let mut vouchers = bad;
        vouchers.extend_from_slice(&good);
        let got = find_book_key(&vouchers, 2, &[pid.to_string()]).unwrap();
        assert_eq!(got, Some(fallback_final));
    }

    #[test]
    fn normalize_pids_truncates_and_expands() {
        // A 10-char explicit PID → first 8 chars; an 8-char PID unchanged; a
        // wrong-length one dropped; each serial contributes two derived PIDs.
        let header = MobiHeader::from_image(&assemble(&mobi_record0(2, 1), b"x").image).unwrap();
        let keys = KeyStore {
            pids: vec![
                "1234567890".to_string(), // 10 → "12345678"
                "ABCDEFGH".to_string(),   // 8 → unchanged
                "short".to_string(),      // dropped
            ],
            serials: vec!["B00120304050607".to_string()],
            ..KeyStore::default()
        };
        let good = normalize_pids(&header, &keys);
        assert!(good.contains(&"12345678".to_string()));
        assert!(good.contains(&"ABCDEFGH".to_string()));
        assert!(!good.iter().any(|p| p == "short"));
        // Two derived PIDs from the one serial, both normalized to 8 chars.
        assert_eq!(good.iter().filter(|p| p.len() != 8).count(), 0);
        assert!(good.len() >= 4); // 2 explicit + 2 derived
    }

    // ---- full-file round trips ----------------------------------------------

    struct SynthMobi {
        image: Vec<u8>,
        rec1_start: usize,
    }

    /// Assemble a 2-section BOOKMOBI (record 0 + one text record). `enc_type`,
    /// the voucher block, and the (already-encrypted) text record are supplied by
    /// the caller. `rec0_body` is the full record-0 image.
    fn assemble(rec0_body: &[u8], rec1: &[u8]) -> SynthMobi {
        const HEADER: usize = 78;
        let table = 2 * 8;
        let rec0_off = HEADER + table;
        let rec1_off = rec0_off + rec0_body.len();

        let mut image = vec![0u8; rec1_off + rec1.len()];
        image[0x3C..0x44].copy_from_slice(b"BOOKMOBI");
        image[0x4C..0x4E].copy_from_slice(&2u16.to_be_bytes());
        image[HEADER..HEADER + 4].copy_from_slice(&(rec0_off as u32).to_be_bytes());
        image[HEADER + 8..HEADER + 12].copy_from_slice(&(rec1_off as u32).to_be_bytes());
        image[rec0_off..rec1_off].copy_from_slice(rec0_body);
        image[rec1_off..].copy_from_slice(rec1);
        SynthMobi { image, rec1_start: rec1_off }
    }

    /// Record-0 image with a MOBI header (version 6, mobi_length 0xE4), no EXTH.
    fn mobi_record0(enc_type: u16, compression: u16) -> Vec<u8> {
        let mobi_length: u32 = 0xE4;
        let mut r = vec![0u8; 16 + mobi_length as usize];
        r[0x00..0x02].copy_from_slice(&compression.to_be_bytes());
        r[0x08..0x0A].copy_from_slice(&1u16.to_be_bytes()); // one text record
        r[0x0C..0x0E].copy_from_slice(&enc_type.to_be_bytes());
        r[0x10..0x14].copy_from_slice(b"MOBI");
        r[0x14..0x18].copy_from_slice(&mobi_length.to_be_bytes());
        r[0x1C..0x20].copy_from_slice(&65001u32.to_be_bytes());
        r[0x68..0x6C].copy_from_slice(&6u32.to_be_bytes());
        r[0x80..0x84].copy_from_slice(&0u32.to_be_bytes()); // no EXTH
        r[0xF2..0xF4].copy_from_slice(&0u16.to_be_bytes()); // extra_data_flags 0
        r
    }

    #[test]
    fn type2_full_round_trip() {
        let pid = "12345678";
        let mut bigpid = pid.as_bytes().to_vec();
        bigpid.resize(16, 0);
        let temp_key = pc1::encrypt(&KEYVEC1, &bigpid).unwrap();
        let finalkey = *b"0123456789abcdef";
        let voucher = make_voucher(&temp_key, 0xCAFE, 0x01, &finalkey);

        // Record 0 = MOBI header + voucher appended right after it.
        let mut rec0 = mobi_record0(2, 1);
        let drm_ptr = rec0.len() as u32;
        rec0[0xA8..0xAC].copy_from_slice(&drm_ptr.to_be_bytes());
        rec0[0xAC..0xB0].copy_from_slice(&1u32.to_be_bytes()); // count
        rec0[0xB0..0xB4].copy_from_slice(&(VOUCHER_LEN as u32).to_be_bytes());
        rec0.extend_from_slice(&voucher);

        let plaintext = b"Hello, Mobipocket world!";
        let rec1 = pc1::encrypt(&finalkey, plaintext).unwrap();
        let synth = assemble(&rec0, &rec1);

        let keys = KeyStore { pids: vec![pid.to_string()], ..KeyStore::default() };
        let book = decrypt(&synth.image, &keys).unwrap();
        assert_eq!(book.extension, "mobi");
        assert_eq!(&book.data[synth.rec1_start..], plaintext);
        // Crypto type at record-0 offset 0x0C is cleared.
        let rec0_start = 78 + 16;
        assert_eq!(&book.data[rec0_start + 0x0C..rec0_start + 0x0E], &[0, 0]);
        // DRM pointers at 0xA8 killed.
        assert_eq!(&book.data[rec0_start + 0xA8..rec0_start + 0xAC], &[0xFF; 4]);
    }

    #[test]
    fn type1_full_round_trip() {
        let finalkey = *b"fedcba9876543210";
        // bookkey_data must PC1-decrypt (under T1_KEYVEC) to finalkey.
        let bookkey_data = pc1::encrypt(T1_KEYVEC, &finalkey).unwrap();

        let mut rec0 = mobi_record0(1, 1);
        let off = 0xE4usize + 16; // mobi_length + 16 → just past the MOBI header
        rec0.resize(off + 16, 0);
        rec0[off..off + 16].copy_from_slice(&bookkey_data);

        let plaintext = b"Old Mobipocket type 1.";
        let rec1 = pc1::encrypt(&finalkey, plaintext).unwrap();
        let synth = assemble(&rec0, &rec1);

        let keys = KeyStore::default();
        let book = decrypt(&synth.image, &keys).unwrap();
        assert_eq!(&book.data[synth.rec1_start..], plaintext);
    }

    #[test]
    fn type0_passes_through() {
        let rec0 = mobi_record0(0, 1);
        let rec1 = b"plain text record".to_vec();
        let synth = assemble(&rec0, &rec1);
        let book = decrypt(&synth.image, &KeyStore::default()).unwrap();
        assert_eq!(book.data, synth.image); // untouched
        assert_eq!(book.extension, "mobi");
    }

    #[test]
    fn type0_print_replica_extension() {
        let rec0 = mobi_record0(0, 1);
        let rec1 = b"%MOP-print-replica".to_vec();
        let synth = assemble(&rec0, &rec1);
        let book = decrypt(&synth.image, &KeyStore::default()).unwrap();
        assert_eq!(book.extension, "azw4");
    }

    #[test]
    fn rental_book_rejected() {
        // Record 0 with an EXTH block carrying a nonzero 406 (expiry) record.
        let mobi_length: u32 = 0xE4;
        let mut rec0 = vec![0u8; 16 + mobi_length as usize];
        rec0[0x08..0x0A].copy_from_slice(&1u16.to_be_bytes());
        rec0[0x0C..0x0E].copy_from_slice(&2u16.to_be_bytes());
        rec0[0x10..0x14].copy_from_slice(b"MOBI");
        rec0[0x14..0x18].copy_from_slice(&mobi_length.to_be_bytes());
        rec0[0x68..0x6C].copy_from_slice(&6u32.to_be_bytes());
        rec0[0x80..0x84].copy_from_slice(&0x40u32.to_be_bytes()); // EXTH present

        // EXTH: one record, type 406, 8-byte nonzero content.
        let mut exth = Vec::new();
        exth.extend_from_slice(b"EXTH");
        let content = 1u64.to_be_bytes();
        let rec_size = 8 + content.len();
        let total = 12 + rec_size;
        exth.extend_from_slice(&(total as u32).to_be_bytes());
        exth.extend_from_slice(&1u32.to_be_bytes()); // nitems
        exth.extend_from_slice(&406u32.to_be_bytes());
        exth.extend_from_slice(&(rec_size as u32).to_be_bytes());
        exth.extend_from_slice(&content);
        rec0.extend_from_slice(&exth);

        let rec1 = vec![0u8; 4];
        let synth = assemble(&rec0, &rec1);
        let err = decrypt(&synth.image, &KeyStore::default()).unwrap_err();
        assert!(matches!(err, SchemeError::RentalBook));
    }

    #[test]
    fn non_mobi_falls_through() {
        let err = decrypt(b"not a palm database at all............", &KeyStore::default())
            .unwrap_err();
        assert!(matches!(err, SchemeError::NotThisScheme));
    }

    #[test]
    fn huff_cdic_keeps_multibyte_bit() {
        // Sanity: header parsing keeps the low bit for HUFF/CDIC compression, so
        // our trailing-data handling would see it. (Round-trip decrypt of real
        // HUFF/CDIC records is out of scope here — decompression is separate.)
        let rec0 = mobi_record0(0, COMPRESSION_HUFF_CDIC);
        let synth = assemble(&rec0, b"x");
        let h = MobiHeader::from_image(&synth.image).unwrap();
        // extra_data_flags default 0 in this synth, but the bit-clear path is
        // exercised in dedrm_formats::mobi tests; assert parse succeeds here.
        assert_eq!(h.compression, COMPRESSION_HUFF_CDIC);
    }
}
