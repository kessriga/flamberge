//! Kindle for Android serial extraction (§6.4).
//!
//! Android doesn't yield a single key; it yields candidate **serials** (the DSN
//! and account tokens) that the PID generators turn into book PIDs. Three
//! sources, ported from `androidkindlekey.py`:
//!
//! * `AmazonSecureStorage.xml` — a shared-preferences file whose keys *and*
//!   values are obfuscated: V1 = AES-128-ECB under a fixed key; V2 (when an
//!   `AmazonSaltKey` is present) = DES-CBC under a key derived by 503 rounds of
//!   MD5. Both PKCS-pad.
//! * `map_data_storage.db` — a SQLite database with the values in the clear.
//! * `backup.ab` — an `adb backup` archive: a 24-byte `ANDROID BACKUP` header
//!   followed by a zlib-compressed tar that contains the two files above.

use std::io::Read;
use std::path::Path;

use flamberge_crypto::{aes, des, digest};

use crate::{KeyError, Result};

/// Basename of the shared-preferences file.
const STORAGE_XML: &str = "AmazonSecureStorage.xml";
/// Basename of the SQLite database.
const STORAGE_DB: &str = "map_data_storage.db";
/// Basename of the `adb backup` archive.
const STORAGE_BACKUP: &str = "backup.ab";

/// Fixed AES-128 key for the V1 obfuscation (`a2b_hex('0176…3523')`).
const V1_KEY: [u8; 16] = [
    0x01, 0x76, 0xe0, 0x4c, 0x94, 0x08, 0xb1, 0x70, 0x2d, 0x90, 0xbe, 0x33, 0x3f, 0xd5, 0x35, 0x23,
];
/// V2 password prefix, MD5-stretched with the salt.
const V2_PASSWORD: &[u8] = b"Thomsun was here!";
/// V2 MD5 stretch count.
const V2_ROUNDS: usize = 503;

/// The obfuscation applied to `AmazonSecureStorage.xml` keys and values.
enum Obfuscation {
    /// AES-128-ECB, 16-byte blocks.
    V1,
    /// DES-CBC, 8-byte blocks.
    V2 { key: [u8; 8], iv: [u8; 8] },
}

impl Obfuscation {
    /// Build the V2 obfuscation from a 16-hex-char `AmazonSaltKey`.
    fn v2(salt_hex: &str) -> Result<Self> {
        let salt = hex::decode(salt_hex)
            .map_err(|_| KeyError::Invalid("AmazonSaltKey is not valid hex".into()))?;
        // key = md5^503(password + salt); DES key/iv are the two halves.
        let mut key = V2_PASSWORD.to_vec();
        key.extend_from_slice(&salt);
        let mut digest = [0u8; 16];
        for _ in 0..V2_ROUNDS {
            digest = digest::md5(&key);
            key = digest.to_vec();
        }
        Ok(Obfuscation::V2 {
            key: digest[..8].try_into().expect("md5 is 16 bytes"),
            iv: digest[8..16].try_into().expect("md5 is 16 bytes"),
        })
    }

    /// Pad modulus / cipher block size.
    fn block(&self) -> usize {
        match self {
            Obfuscation::V1 => 16,
            Obfuscation::V2 { .. } => 8,
        }
    }

    /// Obfuscate a plaintext key name → hex (to look it up in the XML).
    fn encrypt(&self, plaintext: &str) -> Result<String> {
        let block = self.block();
        let mut buf = plaintext.as_bytes().to_vec();
        // PKCS#7 pad to the block size (a full extra block when already aligned).
        let pad = block - (buf.len() % block);
        buf.extend(std::iter::repeat_n(pad as u8, pad));
        let ct = match self {
            Obfuscation::V1 => aes::ecb_encrypt(&V1_KEY, &buf)?,
            Obfuscation::V2 { key, iv } => des::cbc_encrypt(key, iv, &buf)?,
        };
        Ok(hex::encode(ct))
    }

    /// Recover a value from its hex ciphertext, stripping the PKCS#7 pad.
    fn decrypt(&self, cipher_hex: &str) -> Result<Vec<u8>> {
        let ct = hex::decode(cipher_hex)
            .map_err(|_| KeyError::Invalid("obfuscated value is not hex".into()))?;
        let mut pt = match self {
            Obfuscation::V1 => aes::ecb_decrypt(&V1_KEY, &ct)?,
            Obfuscation::V2 { key, iv } => des::cbc_decrypt(key, iv, &ct)?,
        };
        // Strip the pad exactly as the Python does (last byte = pad length).
        if let Some(&n) = pt.last() {
            let n = n as usize;
            if n >= 1 && n <= pt.len() {
                pt.truncate(pt.len() - n);
            }
        }
        Ok(pt)
    }
}

/// Parse an Android shared-preferences XML into a key→value map. Mirrors
/// `parse_preference`: one `<string name="KEY">VALUE</string>` per line.
fn parse_preference(xml: &str) -> std::collections::HashMap<String, String> {
    let mut storage = std::collections::HashMap::new();
    for line in xml.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("<string name=\"") else {
            continue;
        };
        let Some(name_end) = rest.find('"') else {
            continue;
        };
        let key = &rest[..name_end];
        // After the name's closing quote comes `>`, then the value, then `</string>`.
        let after = &rest[name_end + 1..];
        let Some(value) = after
            .strip_prefix('>')
            .and_then(|v| v.strip_suffix("</string>"))
        else {
            continue;
        };
        storage.insert(key.to_string(), value.to_string());
    }
    storage
}

/// Assemble serials from a `dsnid` and its account `tokens` (§6.4): the DSN
/// alone, plus for each token both `dsnid+token` and the bare token.
fn serials_from_dsn_tokens(dsnid: &str, tokens: &[String]) -> Vec<String> {
    let mut serials = Vec::new();
    if !dsnid.is_empty() {
        serials.push(dsnid.to_string());
    }
    let mut seen = std::collections::HashSet::new();
    for token in tokens {
        if token.is_empty() || !seen.insert(token.clone()) {
            continue;
        }
        serials.push(format!("{dsnid}{token}"));
        serials.push(token.clone());
    }
    serials
}

/// Extract serials from an `AmazonSecureStorage.xml` document (`get_serials1`).
fn serials_from_secure_storage(xml: &str) -> Result<Vec<String>> {
    let storage = parse_preference(xml);
    let obfuscation = match storage.get("AmazonSaltKey") {
        Some(salt) if salt.len() == 16 => Obfuscation::v2(salt)?,
        _ => Obfuscation::V1,
    };

    let get_value = |key: &str| -> String {
        obfuscation
            .encrypt(key)
            .ok()
            .and_then(|enc_key| storage.get(&enc_key))
            .and_then(|v| obfuscation.decrypt(v).ok())
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default()
    };

    let dsnid = get_value("DsnId");
    if dsnid.is_empty() {
        return Ok(Vec::new());
    }
    let tokens: Vec<String> = get_value("kindle.account.tokens")
        .split(',')
        .map(|s| s.to_string())
        .collect();
    Ok(serials_from_dsn_tokens(&dsnid, &tokens))
}

/// Extract serials from a `map_data_storage.db` SQLite file (`get_serials2`).
/// Values are stored in the clear; DSNs and account tokens live in two tables.
fn serials_from_database(path: &Path) -> Result<Vec<String>> {
    let conn = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|e| KeyError::Invalid(format!("cannot open map_data_storage.db: {e}")))?;

    let query_column = |sql: &str| -> Result<Vec<String>> {
        let mut stmt = conn
            .prepare(sql)
            .map_err(|e| KeyError::Invalid(format!("map_data_storage query failed: {e}")))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| KeyError::Invalid(format!("map_data_storage query failed: {e}")))?;
        Ok(rows
            .filter_map(|r| r.ok())
            .filter(|s| !s.is_empty())
            .collect())
    };

    let mut dsns = query_column(
        "select device_data_value from device_data \
         where device_data_key like '%serial.number%'",
    )?;
    dsns.sort_unstable();
    dsns.dedup();

    let raw_tokens = query_column(
        "select userdata_value from userdata \
         where userdata_key like '%/%kindle.account.tokens%'",
    )?;
    let mut tokens = Vec::new();
    for value in raw_tokens {
        if value.contains(',') {
            tokens.extend(value.split(',').map(|s| s.to_string()));
        }
        tokens.push(value);
    }
    tokens.sort_unstable();
    tokens.dedup();

    let mut serials = Vec::new();
    for dsn in &dsns {
        serials.push(dsn.clone());
        for token in &tokens {
            serials.push(token.clone());
            serials.push(format!("{dsn}{token}"));
        }
    }
    Ok(serials)
}

/// Extract serials from a `backup.ab` archive: strip the 24-byte header, zlib
/// inflate, untar, and recurse into the two inner files (`get_serials`).
fn serials_from_backup(bytes: &[u8]) -> Result<Vec<String>> {
    if bytes.len() < 24 || &bytes[..14] != b"ANDROID BACKUP" {
        return Err(KeyError::Invalid("not an ANDROID BACKUP archive".into()));
    }
    // The standard unencrypted/compressed header is exactly 24 bytes
    // ("ANDROID BACKUP\n1\n1\nnone\n"); the rest is zlib-compressed tar.
    let mut tar_bytes = Vec::new();
    flate2::read::ZlibDecoder::new(&bytes[24..])
        .read_to_end(&mut tar_bytes)
        .map_err(|e| KeyError::Invalid(format!("backup.ab zlib inflate failed: {e}")))?;

    let mut serials = Vec::new();
    let mut archive = tar::Archive::new(std::io::Cursor::new(tar_bytes));
    let entries = archive
        .entries()
        .map_err(|e| KeyError::Invalid(format!("backup.ab is not a tar: {e}")))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| KeyError::Invalid(format!("backup.ab tar: {e}")))?;
        let name = entry
            .path()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let name = name.trim();
        if name.ends_with(STORAGE_XML) {
            let mut xml = String::new();
            if entry.read_to_string(&mut xml).is_ok() {
                serials.extend(serials_from_secure_storage(&xml)?);
            }
        } else if name.ends_with(STORAGE_DB) {
            let mut db_bytes = Vec::new();
            entry
                .read_to_end(&mut db_bytes)
                .map_err(|e| KeyError::Invalid(format!("backup.ab db read: {e}")))?;
            serials.extend(serials_from_db_bytes(&db_bytes)?);
        }
    }
    serials.sort_unstable();
    serials.dedup();
    Ok(serials)
}

/// Materialize SQLite DB bytes to a temp file and read it (rusqlite needs a path).
fn serials_from_db_bytes(db_bytes: &[u8]) -> Result<Vec<String>> {
    use std::io::Write;
    let mut tmp = tempfile::NamedTempFile::new()
        .map_err(|e| KeyError::Invalid(format!("cannot create temp db: {e}")))?;
    tmp.write_all(db_bytes)
        .map_err(|e| KeyError::Invalid(format!("cannot write temp db: {e}")))?;
    tmp.flush().ok();
    serials_from_database(tmp.path())
}

/// Extract candidate Kindle serials from an Android artifact, dispatching by
/// file name: `backup.ab`, `AmazonSecureStorage.xml`, or `map_data_storage.db`.
pub fn serials_from_android(path: &Path) -> Result<Vec<String>> {
    let basename = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    match basename.as_str() {
        STORAGE_XML => {
            let xml = std::fs::read_to_string(path)
                .map_err(|e| KeyError::NotFound(format!("cannot read {}: {e}", path.display())))?;
            serials_from_secure_storage(&xml)
        }
        STORAGE_DB => serials_from_database(path),
        STORAGE_BACKUP => {
            let bytes = std::fs::read(path)
                .map_err(|e| KeyError::NotFound(format!("cannot read {}: {e}", path.display())))?;
            serials_from_backup(&bytes)
        }
        other => Err(KeyError::Invalid(format!(
            "unrecognized Android artifact `{other}` (expected {STORAGE_BACKUP}, {STORAGE_XML}, or {STORAGE_DB})"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build a shared-preferences XML with the given (already-obfuscated) entries.
    fn build_xml(entries: &[(String, String)]) -> String {
        let mut s = String::from("<?xml version='1.0'?>\n<map>\n");
        for (k, v) in entries {
            s.push_str(&format!("<string name=\"{k}\">{v}</string>\n"));
        }
        s.push_str("</map>\n");
        s
    }

    #[test]
    fn v1_obfuscation_round_trips() {
        let obf = Obfuscation::V1;
        for plain in ["DsnId", "kindle.account.tokens", "a", "sixteen-byte!!!!"] {
            let enc = obf.encrypt(plain).unwrap();
            assert_eq!(obf.decrypt(&enc).unwrap(), plain.as_bytes());
        }
    }

    #[test]
    fn v2_obfuscation_round_trips() {
        let obf = Obfuscation::v2("00112233445566ff").unwrap();
        for plain in ["DsnId", "kindle.account.tokens", "tok"] {
            let enc = obf.encrypt(plain).unwrap();
            assert_eq!(obf.decrypt(&enc).unwrap(), plain.as_bytes());
        }
    }

    #[test]
    fn secure_storage_v1_yields_serials() {
        let obf = Obfuscation::V1;
        let entries = vec![
            (
                obf.encrypt("DsnId").unwrap(),
                obf.encrypt("G000PP12345678").unwrap(),
            ),
            (
                obf.encrypt("kindle.account.tokens").unwrap(),
                obf.encrypt("tokA,tokB").unwrap(),
            ),
        ];
        let xml = build_xml(&entries);
        let serials = serials_from_secure_storage(&xml).unwrap();
        assert!(serials.contains(&"G000PP12345678".to_string()));
        assert!(serials.contains(&"tokA".to_string()));
        assert!(serials.contains(&"G000PP12345678tokA".to_string()));
        assert!(serials.contains(&"tokB".to_string()));
        assert!(serials.contains(&"G000PP12345678tokB".to_string()));
    }

    #[test]
    fn secure_storage_v2_yields_serials() {
        let obf = Obfuscation::v2("0123456789abcdef").unwrap();
        let mut entries = vec![
            ("AmazonSaltKey".to_string(), "0123456789abcdef".to_string()),
            (
                obf.encrypt("DsnId").unwrap(),
                obf.encrypt("G111QQ87654321").unwrap(),
            ),
            (
                obf.encrypt("kindle.account.tokens").unwrap(),
                obf.encrypt("zzz").unwrap(),
            ),
        ];
        // AmazonSaltKey stays in the clear; ordering irrelevant.
        entries.sort();
        let xml = build_xml(&entries);
        let serials = serials_from_secure_storage(&xml).unwrap();
        assert!(serials.contains(&"G111QQ87654321".to_string()));
        assert!(serials.contains(&"zzz".to_string()));
        assert!(serials.contains(&"G111QQ87654321zzz".to_string()));
    }

    fn build_map_db() -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = rusqlite::Connection::open(tmp.path()).unwrap();
        conn.execute_batch(
            "create table device_data(device_data_key text, device_data_value text);
             create table userdata(userdata_key text, userdata_value text);
             insert into device_data values('dsn/serial.number','G222RR11223344');
             insert into userdata values('x/y/kindle.account.tokens','tok1,tok2');",
        )
        .unwrap();
        tmp
    }

    #[test]
    fn map_database_yields_serials() {
        let tmp = build_map_db();
        let serials = serials_from_database(tmp.path()).unwrap();
        assert!(serials.contains(&"G222RR11223344".to_string()));
        assert!(serials.contains(&"tok1".to_string()));
        assert!(serials.contains(&"tok2".to_string()));
        assert!(serials.contains(&"tok1,tok2".to_string()));
        assert!(serials.contains(&"G222RR11223344tok1".to_string()));
    }

    #[test]
    fn backup_ab_untars_and_recurses() {
        let obf = Obfuscation::V1;
        let entries = vec![
            (
                obf.encrypt("DsnId").unwrap(),
                obf.encrypt("G333SS55667788").unwrap(),
            ),
            (
                obf.encrypt("kindle.account.tokens").unwrap(),
                obf.encrypt("aaa").unwrap(),
            ),
        ];
        let xml = build_xml(&entries);

        // tar with apps/com.amazon.kindle/sp/AmazonSecureStorage.xml
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            let data = xml.as_bytes();
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(
                    &mut header,
                    "apps/com.amazon.kindle/sp/AmazonSecureStorage.xml",
                    data,
                )
                .unwrap();
            builder.finish().unwrap();
        }

        // zlib-compress the tar and prepend the 24-byte ANDROID BACKUP header.
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar_buf).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut backup = b"ANDROID BACKUP\n1\n1\nnone\n".to_vec();
        assert_eq!(backup.len(), 24);
        backup.extend_from_slice(&compressed);

        let serials = serials_from_backup(&backup).unwrap();
        assert!(serials.contains(&"G333SS55667788".to_string()));
        assert!(serials.contains(&"aaa".to_string()));
        assert!(serials.contains(&"G333SS55667788aaa".to_string()));
    }
}
