//! Kindle PID generation & encoding (Mobipocket / Topaz / KFX).
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §2.5 / §6.5 (`kgenpids.py`, `kindlepid.py`).

use flamberge_crypto::{crc32, digest};

/// 32-char hash-encoding alphabet (`charMap1`).
pub const CHARMAP1: &[u8] = b"n5Pr6St7Uv8Wx9YzAb0Cd1Ef2Gh3Jk4M";
/// 64-char base64-like alphabet for `encodePID` (`charMap3`).
pub const CHARMAP3: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/// 33-char PID alphabet, no `O`/`0` (`charMap4` / `letters`).
pub const CHARMAP4: &[u8] = b"ABCDEFGHIJKLMNPQRSTUVWXYZ123456789";

/// `encode(data, map)`: each input byte → two output symbols.
pub fn encode(data: &[u8], map: &[u8]) -> Vec<u8> {
    let n = map.len();
    let mut out = Vec::with_capacity(data.len() * 2);
    for &b in data {
        let q = ((b ^ 0x80) as usize) / n;
        let r = (b as usize) % n;
        out.push(map[q]);
        out.push(map[r]);
    }
    out
}

/// `encodeHash(data, map) = encode(MD5(data), map)`.
pub fn encode_hash(data: &[u8], map: &[u8]) -> Vec<u8> {
    encode(&digest::md5(data), map)
}

fn two_bits(field: &[u8], offset: usize) -> u8 {
    let byte_number = offset / 4;
    let bit_position = 6 - 2 * (offset % 4);
    (field[byte_number] >> bit_position) & 3
}

fn six_bits(field: &[u8], offset: usize) -> u8 {
    let o = offset * 3;
    (two_bits(field, o) << 4) + (two_bits(field, o + 1) << 2) + two_bits(field, o + 2)
}

/// `encodePID(hash)` → 8-char PID by reading 8×6-bit groups through `CHARMAP3`.
pub fn encode_pid(hash: &[u8]) -> String {
    let mut pid = String::with_capacity(8);
    for position in 0..8 {
        pid.push(CHARMAP3[six_bits(hash, position) as usize] as char);
    }
    pid
}

/// `checksumPid(s)` → append 2 checksum chars (8-char PID → 10-char PID).
pub fn checksum_pid(s: &str) -> String {
    let mut crc = crc32::flamberge(s.as_bytes());
    crc ^= crc >> 16;
    let l = CHARMAP4.len() as u32;
    let mut res = String::from(s);
    for _ in 0..2 {
        let b = crc & 0xff;
        let pos = (b / l) ^ (b % l);
        res.push(CHARMAP4[(pos % l) as usize] as char);
        crc >>= 8;
    }
    res
}

/// `pidFromSerial(s, l)` — fold serial bytes + CRC into an `l`-char PID.
pub fn pid_from_serial(s: &[u8], l: usize) -> String {
    let crc = crc32::flamberge(s);
    let mut arr = vec![0u8; l];
    for (i, &b) in s.iter().enumerate() {
        arr[i % l] ^= b;
    }
    let crc_bytes = [
        (crc >> 24) as u8,
        (crc >> 16) as u8,
        (crc >> 8) as u8,
        crc as u8,
    ];
    for i in 0..l {
        arr[i] ^= crc_bytes[i & 3];
    }
    let mut pid = String::with_capacity(l);
    for &byte in arr.iter() {
        let b = byte as usize;
        let idx = (b >> 7) + ((b >> 5 & 3) ^ (b & 0x1f));
        pid.push(CHARMAP4[idx] as char);
    }
    pid
}

/// Full book PID from a device serial + DRM metadata (`getKindlePids`, primary).
pub fn book_pid_from_serial(serial: &[u8], rec209: &[u8], token: &[u8]) -> String {
    let mut buf = Vec::with_capacity(serial.len() + rec209.len() + token.len());
    buf.extend_from_slice(serial);
    buf.extend_from_slice(rec209);
    buf.extend_from_slice(token);
    checksum_pid(&encode_pid(&digest::sha1(&buf)))
}

/// eInk Kindle 16-char serial → 10-char PID (`kindlepid.py`).
pub fn eink_pid_from_serial(serial: &str) -> String {
    let base = pid_from_serial(serial.as_bytes(), 7);
    checksum_pid(&format!("{base}*"))
}

/// `generateDevicePID` — a CRC-seeded 8-char PID from the first 4 DSN bytes.
/// (The plugin notes this PID is used for nothing, but it stays in the list.)
///
/// `generatePidSeed` is a reflected CRC-32 (poly `0xEDB88320`, init 0, no final
/// XOR) over `dsn[..4]` — exactly [`crc32::flamberge`], so we reuse it rather
/// than rebuild the 256-entry table per call (§6.5).
fn generate_device_pid(dsn: &[u8]) -> Option<String> {
    if dsn.len() < 4 {
        return None;
    }
    let seed = crc32::flamberge(&dsn[..4]);
    let mut pid = [
        (seed >> 24) as u8,
        (seed >> 16) as u8,
        (seed >> 8) as u8,
        seed as u8,
        (seed >> 24) as u8,
        (seed >> 16) as u8,
        (seed >> 8) as u8,
        seed as u8,
    ];
    let mut index = 0;
    for &b in &dsn[..4] {
        pid[index] ^= b;
        index = (index + 1) % 8;
    }
    let mut out = String::with_capacity(8);
    for &b in &pid {
        let idx = ((((b >> 5) & 3) ^ b) & 0x1f) as usize + (b >> 7) as usize;
        out.push(CHARMAP4[idx] as char);
    }
    Some(out)
}

/// Hex value for `name` in a Kindle DB, decoded to bytes.
fn db_hex(db: &crate::kindle::KindleDb, name: &str) -> Option<Vec<u8>> {
    db.get(name).and_then(|h| hex::decode(h).ok())
}

/// Book PIDs derived from a decoded Kindle key database (`getK4Pids`).
///
/// The account DSN comes from an explicit `DSN` value, or is reconstructed from
/// `MazamaRandomNumber` + the serial/ID string + the (possibly pre-hashed)
/// username (§6.2). Combined with the account token and the book's EXTH-209
/// record + token, this yields the device PID, the primary book PID, and two
/// fallback variants. Returns an empty list when the DB lacks the DSN inputs.
pub fn k4_pids(rec209: &[u8], token: &[u8], db: &crate::kindle::KindleDb) -> Vec<String> {
    let account_token = db_hex(db, "kindle.account.tokens").unwrap_or_default();

    let dsn = match db_hex(db, "DSN") {
        Some(dsn) => dsn,
        None => {
            let Some(mazama) = db_hex(db, "MazamaRandomNumber") else {
                return Vec::new();
            };
            let Some(id_string) = db_hex(db, "SerialNumber").or_else(|| db_hex(db, "IDString"))
            else {
                return Vec::new();
            };
            let encoded_username = match db_hex(db, "UsernameHash") {
                Some(hash) => hash,
                None => match db_hex(db, "UserName") {
                    Some(name) => encode_hash(&name, CHARMAP1),
                    None => return Vec::new(),
                },
            };
            let encoded_id = encode_hash(&id_string, CHARMAP1);
            let mut buf = mazama;
            buf.extend_from_slice(&encoded_id);
            buf.extend_from_slice(&encoded_username);
            encode(&digest::sha1(&buf), CHARMAP1)
        }
    };

    let mut pids = Vec::new();
    if let Some(device_pid) = generate_device_pid(&dsn) {
        pids.push(checksum_pid(&device_pid));
    }
    // Primary book PID and two variants (with/without the DSN or account token).
    let book_pid = |parts: &[&[u8]]| -> String {
        let buf: Vec<u8> = parts.concat();
        checksum_pid(&encode_pid(&digest::sha1(&buf)))
    };
    pids.push(book_pid(&[&dsn, &account_token, rec209, token]));
    pids.push(book_pid(&[&account_token, rec209, token]));
    pids.push(book_pid(&[&dsn, rec209, token]));
    pids
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_pid_is_eight_chars() {
        let hash = digest::sha1(b"B00120304050607*rec209token");
        assert_eq!(encode_pid(&hash).len(), 8);
    }

    #[test]
    fn checksum_adds_two_chars() {
        let base = "ABCD1234";
        let full = checksum_pid(base);
        assert_eq!(full.len(), 10);
        assert!(full.starts_with(base));
    }

    #[test]
    fn k4_pids_from_explicit_dsn() {
        // A DB with a direct DSN + account token yields the device PID plus the
        // primary book PID and two variants — four 10-char PIDs.
        let mut db = crate::kindle::KindleDb::new();
        db.insert("DSN".into(), hex::encode(b"device-serial-number"));
        db.insert("kindle.account.tokens".into(), hex::encode(b"acct-token"));
        let pids = k4_pids(b"\x00rec209data", b"tokenbytes", &db);
        assert_eq!(pids.len(), 4);
        for p in &pids {
            assert_eq!(p.len(), 10, "each book PID is 10 chars: {p}");
        }
    }

    #[test]
    fn k4_pids_derives_dsn_from_mazama() {
        // No DSN key: reconstruct it from MazamaRandomNumber + serial + username.
        let mut db = crate::kindle::KindleDb::new();
        db.insert("MazamaRandomNumber".into(), hex::encode(b"mazama-rand"));
        db.insert("SerialNumber".into(), hex::encode(b"B00XYZ"));
        db.insert("UserName".into(), hex::encode(b"alice"));
        db.insert("kindle.account.tokens".into(), hex::encode(b"acct"));
        let pids = k4_pids(b"rec", b"tok", &db);
        assert_eq!(pids.len(), 4);
    }

    #[test]
    fn k4_pids_empty_without_dsn_inputs() {
        let db = crate::kindle::KindleDb::new();
        assert!(k4_pids(b"rec", b"tok", &db).is_empty());
    }

    #[test]
    fn eink_pid_is_ten_chars() {
        // Structure: 7 CHARMAP4 chars from the serial, a literal '*', then 2
        // CHARMAP4 checksum chars.
        let pid = eink_pid_from_serial("B001234567890123");
        assert_eq!(pid.len(), 10);
        let bytes = pid.as_bytes();
        assert_eq!(bytes[7], b'*');
        for &c in bytes.iter().take(7).chain(bytes.iter().skip(8)) {
            assert!(CHARMAP4.contains(&c), "unexpected PID char: {}", c as char);
        }
    }
}
