//! Topaz (TPZ) DRM removal.
//!
//! Flow (§5): parse the `TPZ0` container → read the `dkey` record → for each
//! candidate PID (8 bytes) Topaz-decrypt every dkey sub-record and validate the
//! `PID..pid` magic plus embedded PID → recover the 8-byte book key →
//! Topaz-decrypt (then zlib-inflate) the encrypted payload records. Books with
//! no `dkey` record are already unencrypted.
//!
//! Output is a **repackaged, decrypted `TPZ0` container** (extension `tpz`):
//! every record is stored in the clear and uncompressed, the `dkey` key store
//! is dropped, and `metadata` is preserved. Rebuilding readable HTML/SVG
//! (`genbook.py` / `flatxml2html.py`) is out of scope — see spec §5.5–5.6.
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §5.2–5.4. Original: `topazextract.py`
//! (`processBook`, `decryptDkeyRecords`, `getBookPayloadRecord`).

use std::io::Read;

use crate::{DecryptedBook, KeyStore, Result, SchemeError};
use flamberge_crypto::topaz::TopazCipher;
use flamberge_formats::topaz_container::{Metadata, RecordEntry, TopazContainer};
use flamberge_formats::FormatError;
use flamberge_keys::pid;
use flate2::read::ZlibDecoder;

/// Length of one dkey sub-record after Topaz decryption (`struct '3sB8sB8s3s'`).
const DKEY_SUBRECORD_LEN: usize = 24;
/// Length of a Topaz PID / book key.
const KEY_LEN: usize = 8;

/// Whether `data` looks like a Topaz container.
pub fn detect(data: &[u8]) -> bool {
    data.starts_with(b"TPZ")
}

/// Remove Topaz DRM from a full `TPZ0` file image, returning a repackaged
/// decrypted container.
pub fn decrypt(input: &[u8], keys: &KeyStore) -> Result<DecryptedBook> {
    if !detect(input) {
        return Err(SchemeError::NotThisScheme);
    }

    let container = TopazContainer::parse(input)?;
    // Metadata is normally present; tolerate its absence rather than failing.
    let metadata = container.parse_metadata(input).ok();

    let title = metadata
        .as_ref()
        .and_then(|m| m.get(b"Title"))
        .map(|t| String::from_utf8_lossy(t).into_owned());

    // §5.4: recover the book key from the dkey record. No dkey ⇒ unencrypted.
    let book_key = match read_dkey_blob(&container, input)? {
        Some(blob) => {
            let pids = candidate_pids(metadata.as_ref(), keys);
            Some(find_book_key(&blob, &pids).ok_or(SchemeError::NoKeyWorked)?)
        }
        None => None,
    };

    let data = repackage(&container, input, metadata.as_ref(), book_key)?;
    Ok(DecryptedBook {
        data,
        extension: "tpz".to_owned(),
        title,
    })
}

/// Read the raw `dkey[0]` blob (inflated if compressed), or `None` when the
/// container has no `dkey` record (an already-unencrypted book). The dkey record
/// itself is never Topaz-encrypted; only its sub-records are (§5.4).
fn read_dkey_blob(container: &TopazContainer, input: &[u8]) -> Result<Option<Vec<u8>>> {
    if !container.header_records.contains_key(b"dkey".as_slice()) {
        return Ok(None);
    }
    let record = container.payload_record(input, b"dkey", 0)?;
    let blob = if record.compressed {
        zlib_inflate(record.raw)?
    } else {
        record.raw.to_vec()
    };
    Ok(Some(blob))
}

/// Candidate 8-byte PIDs: user-supplied PIDs plus PIDs derived from each device
/// serial, every entry truncated to its first 8 bytes (`pid[0:8]`, §5.4). PID
/// generation mirrors Mobipocket (§2.5): `md1 = keys`, `md2 = token`.
fn candidate_pids(metadata: Option<&Metadata>, keys: &KeyStore) -> Vec<[u8; KEY_LEN]> {
    let (md1, md2) = metadata.map(Metadata::pid_meta).unwrap_or_default();

    let mut raw: Vec<String> = keys.pids.clone();
    for serial in &keys.serials {
        raw.push(pid::book_pid_from_serial(serial.as_bytes(), &md1, &md2));
        raw.push(pid::eink_pid_from_serial(serial));
    }

    let mut out = Vec::with_capacity(raw.len());
    for candidate in raw {
        let bytes = candidate.as_bytes();
        if bytes.len() >= KEY_LEN {
            let mut pid = [0u8; KEY_LEN];
            pid.copy_from_slice(&bytes[..KEY_LEN]);
            out.push(pid);
        }
    }
    out
}

/// Try every candidate PID against every dkey sub-record; return the first
/// structurally valid 8-byte book key (`decryptDkeyRecords`).
///
/// Blob layout: `nbKeyRecords` (1 byte), then `nbKeyRecords ×
/// [len (1 byte), subRecord (len bytes)]`. A sub-record is Topaz-decrypted with
/// the candidate PID and validated by [`validate_dkey`]; a wrong PID yields
/// garbage that fails the magic/self-check, so the next candidate is tried.
fn find_book_key(blob: &[u8], pids: &[[u8; KEY_LEN]]) -> Option<[u8; KEY_LEN]> {
    let nb_records = *blob.first()? as usize;
    for pid in pids {
        let mut pos = 1usize;
        for _ in 0..nb_records {
            let len = *blob.get(pos)? as usize;
            pos += 1;
            let sub = blob.get(pos..pos.checked_add(len)?)?;
            pos += len;
            if len == DKEY_SUBRECORD_LEN {
                let decrypted = TopazCipher::new(pid).decrypt(sub);
                if let Some(book_key) = validate_dkey(&decrypted, pid) {
                    return Some(book_key);
                }
            }
        }
    }
    None
}

/// Validate a decrypted 24-byte dkey sub-record (`struct '3sB8sB8s3s'`, §5.4)
/// and extract the embedded book key. The record must bear the `PID`/`pid`
/// magic, both length fields must be 8, and the embedded PID must equal the
/// candidate PID that decrypted it (the self-check).
fn validate_dkey(decrypted: &[u8], pid: &[u8; KEY_LEN]) -> Option<[u8; KEY_LEN]> {
    if decrypted.len() != DKEY_SUBRECORD_LEN {
        return None;
    }
    let magic_ok = &decrypted[0..3] == b"PID" && &decrypted[21..24] == b"pid";
    let lengths_ok = decrypted[3] == 8 && decrypted[12] == 8;
    let pid_ok = &decrypted[4..12] == pid;
    if !(magic_ok && lengths_ok && pid_ok) {
        return None;
    }
    let mut book_key = [0u8; KEY_LEN];
    book_key.copy_from_slice(&decrypted[13..21]);
    Some(book_key)
}

/// Rebuild a decrypted `TPZ0` container: decrypt/inflate every payload record,
/// drop the `dkey` key store, and preserve `metadata`. Record offsets are
/// recomputed relative to the new payload region (§5.2).
fn repackage(
    container: &TopazContainer,
    input: &[u8],
    metadata: Option<&Metadata>,
    book_key: Option<[u8; KEY_LEN]>,
) -> Result<Vec<u8>> {
    // Deterministic record order (the source is a HashMap).
    let mut items: Vec<(&Vec<u8>, &Vec<RecordEntry>)> = container.header_records.iter().collect();
    items.sort_by(|a, b| a.0.cmp(b.0));

    let mut payload: Vec<u8> = Vec::new();
    let mut header_records: Vec<(Vec<u8>, Vec<RecordEntry>)> = Vec::new();

    for (name, entries) in items {
        if name.as_slice() == b"dkey" {
            continue; // key store — never emitted (§5.2)
        }

        if name.as_slice() == b"metadata" {
            // The metadata record has no encoded index field, so it cannot be
            // read (or re-emitted) via the generic payload path; serialize it
            // from the parsed key/value map instead.
            let meta = metadata.ok_or_else(|| {
                SchemeError::Format(FormatError::Invalid("metadata record missing".to_owned()))
            })?;
            let body = serialize_metadata(meta)?;
            let offset = payload.len() as u64;
            payload.extend_from_slice(&encode_lp_string(b"metadata"));
            payload.extend_from_slice(&body);
            header_records.push((
                name.clone(),
                vec![RecordEntry {
                    offset,
                    decompressed_len: body.len() as u64,
                    compressed_len: 0,
                }],
            ));
            continue;
        }

        let mut out_entries = Vec::with_capacity(entries.len());
        for index in 0..entries.len() {
            let record = container.payload_record(input, name.as_slice(), index)?;

            // Pipeline: Topaz-decrypt (if flagged) then zlib-inflate (§5.2).
            let mut bytes = record.raw.to_vec();
            if record.encrypted {
                let key = book_key.ok_or(SchemeError::NoKeyWorked)?;
                bytes = TopazCipher::new(&key).decrypt(&bytes);
            }
            if record.compressed {
                bytes = zlib_inflate(&bytes)?;
            }

            let offset = payload.len() as u64;
            payload.extend_from_slice(&encode_lp_string(name));
            payload.extend_from_slice(&encode_number(index as i64));
            payload.extend_from_slice(&bytes);
            out_entries.push(RecordEntry {
                offset,
                decompressed_len: bytes.len() as u64,
                compressed_len: 0, // stored uncompressed
            });
        }
        header_records.push((name.clone(), out_entries));
    }

    // Assemble: "TPZ0" | header | 0x64 | payload.
    let mut out = Vec::with_capacity(4 + payload.len() + 64);
    out.extend_from_slice(b"TPZ0");
    out.extend_from_slice(&encode_number(header_records.len() as i64));
    for (name, entries) in &header_records {
        out.push(0x63); // header-record marker
        out.extend_from_slice(&encode_lp_string(name));
        out.extend_from_slice(&encode_number(entries.len() as i64));
        for entry in entries {
            out.extend_from_slice(&encode_number(entry.offset as i64));
            out.extend_from_slice(&encode_number(entry.decompressed_len as i64));
            out.extend_from_slice(&encode_number(entry.compressed_len as i64));
        }
    }
    out.push(0x64); // end-of-headers marker
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Serialize a metadata record body: 1-byte flags (0), 1-byte count, then
/// `count` length-prefixed `[key, value]` pairs (§5.2). The tag is written by
/// the caller.
fn serialize_metadata(meta: &Metadata) -> Result<Vec<u8>> {
    let count = u8::try_from(meta.entries.len()).map_err(|_| {
        SchemeError::Format(FormatError::Invalid(
            "metadata has more than 255 entries".to_owned(),
        ))
    })?;
    let mut out = Vec::new();
    out.push(0x00); // flags (unused by DeDRM)
    out.push(count);
    for (key, value) in &meta.entries {
        out.extend_from_slice(&encode_lp_string(key));
        out.extend_from_slice(&encode_lp_string(value));
    }
    Ok(out)
}

/// Zlib-inflate a record (standard 2-byte-header zlib, not raw DEFLATE, §5.2).
fn zlib_inflate(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    ZlibDecoder::new(data).read_to_end(&mut out).map_err(|e| {
        SchemeError::Format(FormatError::Invalid(format!("zlib inflate failed: {e}")))
    })?;
    Ok(out)
}

/// Encode an integer as a Topaz encoded-number: the inverse of
/// [`flamberge_formats::topaz_container::read_encoded_number`] (§5.1).
fn encode_number(n: i64) -> Vec<u8> {
    let mut out = Vec::new();
    if n < 0 {
        out.push(0xFF); // negative-sign marker
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
    // A positive value must not start with 0xFF (which marks a negative). When
    // the leading group is 0x7F its continuation byte becomes 0xFF, so prepend a
    // zero continuation group to disambiguate (the canonical container form).
    if n > 0 && groups[0] == 0x7F {
        groups.insert(0, 0x00);
    }
    let last = groups.len() - 1;
    for (i, group) in groups.iter().enumerate() {
        out.push(if i < last { group | 0x80 } else { *group });
    }
    out
}

/// Encode a length-prefixed string: encoded-number length then the raw bytes.
fn encode_lp_string(s: &[u8]) -> Vec<u8> {
    let mut out = encode_number(s.len() as i64);
    out.extend_from_slice(s);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    const PID: [u8; KEY_LEN] = *b"12345678";
    const BOOK_KEY: [u8; KEY_LEN] = *b"BOOKKEY!";

    fn zlib_deflate(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    /// A dkey sub-record encrypted under `pid` embedding `book_key`.
    fn dkey_subrecord(pid: &[u8; KEY_LEN], book_key: &[u8; KEY_LEN]) -> Vec<u8> {
        let mut sub = Vec::new();
        sub.extend_from_slice(b"PID");
        sub.push(8);
        sub.extend_from_slice(pid);
        sub.push(8);
        sub.extend_from_slice(book_key);
        sub.extend_from_slice(b"pid");
        assert_eq!(sub.len(), DKEY_SUBRECORD_LEN);
        TopazCipher::new(pid).encrypt(&sub)
    }

    /// One payload record body: `lp(name) | encoded-index | stored-bytes`, with
    /// the index made negative (`-index - 1`) when `encrypted`.
    fn payload_record(name: &[u8], index: usize, encrypted: bool, stored: &[u8]) -> Vec<u8> {
        let mut out = encode_lp_string(name);
        let stored_index = if encrypted {
            -(index as i64) - 1
        } else {
            index as i64
        };
        out.extend_from_slice(&encode_number(stored_index));
        out.extend_from_slice(stored);
        out
    }

    /// A page record (index 0) whose plaintext is `content`, Topaz-encrypted
    /// under `BOOK_KEY` and optionally zlib-compressed first.
    fn encrypted_page(content: &[u8], compressed: bool) -> (Vec<u8>, u64, u64) {
        let staged = if compressed {
            zlib_deflate(content)
        } else {
            content.to_vec()
        };
        let stored = TopazCipher::new(&BOOK_KEY).encrypt(&staged);
        let decompressed_len = content.len() as u64;
        let compressed_len = if compressed { stored.len() as u64 } else { 0 };
        (stored, decompressed_len, compressed_len)
    }

    /// A fixture record: name, its `(decompressed_len, compressed_len)` entries,
    /// and the raw payload body.
    type FixtureRecord<'a> = (&'a [u8], Vec<(u64, u64)>, Vec<u8>);

    /// Assemble a full `TPZ0` file from records laid out consecutively in the
    /// payload region.
    fn build_file(records: &[FixtureRecord]) -> Vec<u8> {
        let mut payload = Vec::new();
        let mut offsets = Vec::new();
        for (_, _, body) in records {
            offsets.push(payload.len() as u64);
            payload.extend_from_slice(body);
        }

        let mut header = encode_number(records.len() as i64);
        for (i, (name, entries, _)) in records.iter().enumerate() {
            header.push(0x63);
            header.extend_from_slice(&encode_lp_string(name));
            header.extend_from_slice(&encode_number(entries.len() as i64));
            // Single-entry records in these fixtures start at the record offset.
            let mut entry_offset = offsets[i];
            for (decompressed_len, compressed_len) in entries {
                header.extend_from_slice(&encode_number(entry_offset as i64));
                header.extend_from_slice(&encode_number(*decompressed_len as i64));
                header.extend_from_slice(&encode_number(*compressed_len as i64));
                let stored = if *compressed_len > 0 {
                    *compressed_len
                } else {
                    *decompressed_len
                };
                entry_offset += stored;
            }
        }

        let mut file = Vec::new();
        file.extend_from_slice(b"TPZ0");
        file.extend_from_slice(&header);
        file.push(0x64);
        file.extend_from_slice(&payload);
        file
    }

    fn metadata_record(pairs: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut body = encode_lp_string(b"metadata");
        body.push(0x00);
        body.push(pairs.len() as u8);
        for (k, v) in pairs {
            body.extend_from_slice(&encode_lp_string(k));
            body.extend_from_slice(&encode_lp_string(v));
        }
        body
    }

    fn keys_with_pid(pid: &str) -> KeyStore {
        KeyStore {
            pids: vec![pid.to_owned()],
            ..KeyStore::new()
        }
    }

    /// A container with a dkey plus an uncompressed and a compressed encrypted
    /// page, and a metadata record carrying a title.
    fn encrypted_book() -> (Vec<u8>, &'static [u8], &'static [u8]) {
        let plain0: &[u8] = b"Topaz secret record contents.";
        let plain1: &[u8] = b"Second, compressed and encrypted, record body.";

        let dkey_blob = {
            let sub = dkey_subrecord(&PID, &BOOK_KEY);
            let mut blob = vec![1u8, sub.len() as u8];
            blob.extend_from_slice(&sub);
            blob
        };
        // A record entry's length counts only the stored data, i.e. the bytes
        // after the tag + encoded index that a payload record reads.
        let dkey_len = dkey_blob.len() as u64;
        let dkey_body = payload_record(b"dkey", 0, false, &dkey_blob);

        let (page0, dl0, cl0) = encrypted_page(plain0, false);
        let (page1, dl1, cl1) = encrypted_page(plain1, true);
        let page0_body = payload_record(b"page0", 0, true, &page0);
        let page1_body = payload_record(b"page1", 0, true, &page1);

        let meta_body = metadata_record(&[(b"Title", b"Topaz Test Book")]);

        let file = build_file(&[
            (b"metadata", vec![(0, 0)], meta_body),
            (b"dkey", vec![(dkey_len, 0)], dkey_body),
            (b"page0", vec![(dl0, cl0)], page0_body),
            (b"page1", vec![(dl1, cl1)], page1_body),
        ]);
        (file, plain0, plain1)
    }

    #[test]
    fn decrypts_records_with_correct_pid() {
        let (file, plain0, plain1) = encrypted_book();
        let keys = keys_with_pid("12345678");

        let book = decrypt(&file, &keys).unwrap();
        assert_eq!(book.extension, "tpz");
        assert_eq!(book.title.as_deref(), Some("Topaz Test Book"));

        // The output is a decrypted TPZ0 our own parser round-trips.
        let out = TopazContainer::parse(&book.data).unwrap();
        assert!(!out.header_records.contains_key(b"dkey".as_slice())); // dropped

        let r0 = out.payload_record(&book.data, b"page0", 0).unwrap();
        assert!(!r0.encrypted && !r0.compressed);
        assert_eq!(r0.raw, plain0);

        // The compressed+encrypted record came back inflated in the clear.
        let r1 = out.payload_record(&book.data, b"page1", 0).unwrap();
        assert!(!r1.encrypted && !r1.compressed);
        assert_eq!(r1.raw, plain1);
    }

    #[test]
    fn correct_pid_selected_among_wrong_ones() {
        let (file, plain0, _) = encrypted_book();
        let keys = KeyStore {
            pids: vec![
                "WRONGPID".to_owned(),
                "badbadba".to_owned(),
                "12345678".to_owned(),
            ],
            ..KeyStore::new()
        };

        let book = decrypt(&file, &keys).unwrap();
        let out = TopazContainer::parse(&book.data).unwrap();
        let r0 = out.payload_record(&book.data, b"page0", 0).unwrap();
        assert_eq!(r0.raw, plain0);
    }

    #[test]
    fn wrong_pid_is_rejected() {
        let (file, _, _) = encrypted_book();
        let keys = keys_with_pid("WRONGPID");
        assert!(matches!(
            decrypt(&file, &keys),
            Err(SchemeError::NoKeyWorked)
        ));
    }

    #[test]
    fn no_dkey_is_treated_as_unencrypted() {
        // A container with only an unencrypted page and metadata, no dkey.
        let plain: &[u8] = b"plaintext page, no DRM here";
        let page_body = payload_record(b"page", 0, false, plain);
        let meta_body = metadata_record(&[(b"Title", b"Clear Book")]);
        let file = build_file(&[
            (b"metadata", vec![(0, 0)], meta_body),
            (b"page", vec![(plain.len() as u64, 0)], page_body),
        ]);

        // No PIDs needed for an unencrypted book.
        let book = decrypt(&file, &KeyStore::new()).unwrap();
        assert_eq!(book.title.as_deref(), Some("Clear Book"));
        let out = TopazContainer::parse(&book.data).unwrap();
        let r = out.payload_record(&book.data, b"page", 0).unwrap();
        assert_eq!(r.raw, plain);
    }

    #[test]
    fn non_topaz_falls_through() {
        assert!(matches!(
            decrypt(b"not a topaz file", &KeyStore::new()),
            Err(SchemeError::NotThisScheme)
        ));
    }

    #[test]
    fn encode_number_round_trips() {
        use flamberge_formats::topaz_container::read_encoded_number;
        for n in [0i64, 1, 8, 127, 128, 300, 16384, 1_000_000, -1, -2, -300] {
            let bytes = encode_number(n);
            assert_eq!(
                read_encoded_number(&bytes).unwrap(),
                (n, bytes.len()),
                "n={n}"
            );
        }
    }
}
