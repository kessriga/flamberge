//! `.kinf2011` / `.kinf2018` container decryption (§6.2, §6.3).
//!
//! A `.kinf` file is a `/`-joined list of records. The first record is an
//! encrypted header carrying the `[Version][Build][Guid]` entropy; the rest are
//! grouped into key records (a 32-byte name hash, a record count, then that many
//! obfuscated value records). Each value is de-rotated, [`decode`]d with
//! [`TESTMAP8`], and finally decrypted:
//!
//! * **v5 `.kinf2011`** — Windows uses real DPAPI (out of reach offline); macOS
//!   uses an emulated DPAPI (PBKDF2 + AES-256-CBC) that we reproduce here.
//! * **v6 `.kinf2018`** — AES-256 GCM implemented as CTR, on both platforms.
//!
//! Ported from `kindlekey.py::getDBfromFile`.

use std::sync::LazyLock;

use flamberge_crypto::{aes, digest, kdf};

use super::obfuscation::{decode, derotate, encode, encode_hash, Platform, CHARMAP1, TESTMAP8};
use super::KindleDb;
use crate::{KeyError, Result};

/// Header PBKDF2 password (`kindlekey.py::UnprotectHeaderData`).
const HEADER_PASSWORD: &[u8] = b"header_key_data";
/// Header PBKDF2 salt.
const HEADER_SALT: &[u8] = b"HEADER.2011";
/// Separator woven into every derived-key password: `USER + SEP + IDString`.
const PASSWORD_SEP: &[u8] = b"+@#$%+";

/// Build the derived-key password material `user_name + SEP + id_string`, shared
/// by the v5 (Mac) and v6 key derivations.
fn password_material(user_name: &[u8], id_string: &[u8]) -> Vec<u8> {
    let mut sp = Vec::with_capacity(user_name.len() + PASSWORD_SEP.len() + id_string.len());
    sp.extend_from_slice(user_name);
    sp.extend_from_slice(PASSWORD_SEP);
    sp.extend_from_slice(id_string);
    sp
}

/// The key-name dictionary. `namehashmap[encodeHash(name, testMap8)] = name`
/// recovers readable names for the records whose hash matches; unknown records
/// keep their raw hash as the name (§6.2).
const NAMES: &[&str] = &[
    "kindle.account.tokens",
    "kindle.cookie.item",
    "eulaVersionAccepted",
    "login_date",
    "kindle.token.item",
    "login",
    "kindle.key.item",
    "kindle.name.info",
    "kindle.device.info",
    "MazamaRandomNumber",
    "max_date",
    "SIGVERIF",
    "build_version",
    "SerialNumber",
    "UsernameHash",
    "kindle.directedid.info",
    "DSN",
    "kindle.accounttype.info",
    "krx.flashcardsplugin.data.encryption_key",
    "krx.notebookexportplugin.data.encryption_key",
    "proxy.http.password",
    "proxy.http.username",
];

/// The `[Version][Build][Guid]` entropy recovered from the header.
struct HeaderFields {
    version: u32,
    build: u64,
    guid: Vec<u8>,
}

/// Decrypt the `.kinf` header (key-independent) and return the entropy fields.
fn parse_header(header_blob: &[u8]) -> Result<HeaderFields> {
    let ciphertext = decode(header_blob, CHARMAP1);
    let key_iv = kdf::pbkdf2_sha1(HEADER_PASSWORD, HEADER_SALT, 0x80, 0x100);
    // key = [0:32], iv = [32:48]; AES-256-CBC, no padding (we regex the plaintext).
    let cleartext = aes::cbc_decrypt(&key_iv[0..32], &key_iv[32..48], &ciphertext)?;
    parse_header_fields(&cleartext)
        .ok_or_else(|| KeyError::Invalid("kinf header missing Version/Build/Guid".into()))
}

/// Extract `[Version:N][Build:N]...[Guid:...]` from the decrypted header bytes.
fn parse_header_fields(cleartext: &[u8]) -> Option<HeaderFields> {
    let version = ascii_between(cleartext, b"[Version:", b']')?;
    let build = ascii_between(cleartext, b"[Build:", b']')?;
    let guid = bytes_between(cleartext, b"[Guid:", b']')?;
    Some(HeaderFields {
        version: std::str::from_utf8(&version).ok()?.parse().ok()?,
        build: std::str::from_utf8(&build).ok()?.parse().ok()?,
        guid: guid.to_vec(),
    })
}

/// Bytes after `tag` up to (excluding) the next `end` byte.
fn bytes_between<'a>(hay: &'a [u8], tag: &[u8], end: u8) -> Option<&'a [u8]> {
    let start = find(hay, tag)? + tag.len();
    let rest = &hay[start..];
    let stop = rest.iter().position(|&b| b == end)?;
    Some(&rest[..stop])
}

fn ascii_between(hay: &[u8], tag: &[u8], end: u8) -> Option<Vec<u8>> {
    bytes_between(hay, tag, end).map(|s| s.to_vec())
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// The macOS emulated-DPAPI decryptor (`CryptUnprotectData` in the Mac branch).
/// Built once per `(entropy, id_string)`; decrypts each record's value (§6.3).
struct MacCud {
    key: Vec<u8>,
    iv: Vec<u8>,
    charmap2: &'static [u8],
}

impl MacCud {
    fn new(entropy: &[u8], user_name: &[u8], id_string: &[u8], platform: Platform) -> Self {
        let charmap2 = platform.charmap2();
        let passwd = encode(
            &digest::sha256(&password_material(user_name, id_string)),
            charmap2,
        );
        let key_iv = kdf::pbkdf2_sha1(&passwd, entropy, 0x800, 0x400);
        MacCud {
            key: key_iv[0..32].to_vec(),
            iv: key_iv[32..48].to_vec(),
            charmap2,
        }
    }

    fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        let cleartext = aes::cbc_decrypt(&self.key, &self.iv, encrypted)?;
        Ok(decode(&cleartext, self.charmap2))
    }
}

/// Version-specific key material prepared once for the whole file.
enum Decryptor {
    /// macOS v5 `.kinf2011` emulated DPAPI.
    MacV5 { cud: MacCud },
    /// v6 `.kinf2018` GCM-as-CTR: a 32-byte AES key + the value char map.
    V6 {
        key: Vec<u8>,
        charmap5: &'static [u8],
    },
}

impl Decryptor {
    fn build(
        header: &HeaderFields,
        platform: Platform,
        user_name: &[u8],
        id_string: &[u8],
    ) -> Result<Self> {
        match header.version {
            5 => match platform {
                Platform::Mac => {
                    // entropy = str(0x2df * build) + guid
                    let mut entropy = (0x2df * header.build).to_string().into_bytes();
                    entropy.extend_from_slice(&header.guid);
                    Ok(Decryptor::MacV5 {
                        cud: MacCud::new(&entropy, user_name, id_string, platform),
                    })
                }
                Platform::Pc => Err(KeyError::Unsupported(
                    "Windows .kinf2011 (v5) needs real DPAPI with the user's profile",
                )),
            },
            6 => {
                let charmap5 = platform.charmap5();
                // salt = str(0x6d8 * build) + guid
                let mut salt = (0x6d8 * header.build).to_string().into_bytes();
                salt.extend_from_slice(&header.guid);
                let passwd = encode(
                    &digest::sha256(&password_material(user_name, id_string)),
                    charmap5,
                );
                let key = kdf::pbkdf2_sha1(&passwd, &salt, 10000, 0x400)[..32].to_vec();
                Ok(Decryptor::V6 { key, charmap5 })
            }
            v => Err(KeyError::Invalid(format!("unsupported .kinf version {v}"))),
        }
    }

    /// Decrypt one de-rotated value record into its cleartext bytes.
    fn decrypt_value(&self, derotated: &[u8]) -> Result<Vec<u8>> {
        match self {
            Decryptor::MacV5 { cud } => {
                let encrypted = decode(derotated, TESTMAP8);
                cud.decrypt(&encrypted)
            }
            Decryptor::V6 { key, charmap5 } => {
                let iv_ct = decode(derotated, TESTMAP8);
                if iv_ct.len() < 12 {
                    return Err(KeyError::Invalid(
                        "kinf2018 value shorter than nonce".into(),
                    ));
                }
                // 12-byte GCM nonce + counter suffix 0x00000002 (block 1 is the
                // tag, which GCM-as-CTR ignores).
                let mut iv = [0u8; 16];
                iv[..12].copy_from_slice(&iv_ct[..12]);
                iv[15] = 0x02;
                let plain = aes::ctr_apply(key, &iv, &iv_ct[12..])?;
                Ok(decode(&plain, charmap5))
            }
        }
    }
}

/// Decrypt a `.kinf` file for one `(user_name, id_string)` candidate.
///
/// Returns the recovered database (name → hex value). Succeeds only when more
/// than six values decrypt (the plugin's heuristic that the candidate was
/// correct); otherwise returns [`KeyError::NotFound`] so a caller can try the
/// next candidate. `IDString`/`UserName` are added to the DB for `getK4Pids`.
pub fn decrypt_kinf(
    data: &[u8],
    platform: Platform,
    user_name: &[u8],
    id_string: &[u8],
) -> Result<KindleDb> {
    // Drop the trailing '/' before splitting (kindlekey.py: `data = data[:-1]`).
    let trimmed = data.strip_suffix(b"/").unwrap_or(data);
    let mut items = trimmed.split(|&b| b == b'/');

    let header_blob = items
        .next()
        .ok_or_else(|| KeyError::Invalid("empty .kinf file".into()))?;
    let header = parse_header(header_blob)?;
    let decryptor = Decryptor::build(&header, platform, user_name, id_string)?;

    let charmap5 = platform.charmap5();

    let items: Vec<&[u8]> = items.collect();
    let mut db = KindleDb::new();
    let mut idx = 0;
    while idx < items.len() {
        let item = items[idx];
        idx += 1;
        if item.len() < 34 {
            continue;
        }
        let keyhash = &item[0..32];
        let rcnt: usize = match std::str::from_utf8(&decode(&item[34..], charmap5))
            .ok()
            .and_then(|s| s.trim().parse().ok())
        {
            Some(n) => n,
            None => continue,
        };
        if idx + rcnt > items.len() {
            break;
        }
        let encdata: Vec<u8> = items[idx..idx + rcnt].concat();
        idx += rcnt;

        let keyname = NAME_HASH_MAP
            .get(keyhash)
            .map(|name| (*name).to_string())
            .unwrap_or_else(|| String::from_utf8_lossy(keyhash).into_owned());

        let derotated = derotate(&encdata);
        let cleartext = decryptor.decrypt_value(&derotated)?;
        if !cleartext.is_empty() {
            db.insert(keyname, hex::encode(cleartext));
        }
    }

    if db.len() > 6 {
        db.insert("IDString".into(), hex::encode(id_string));
        db.insert("UserName".into(), hex::encode(user_name));
        Ok(db)
    } else {
        Err(KeyError::NotFound(
            "no .kinf values decrypted (wrong UserName/IDString?)".into(),
        ))
    }
}

/// Try each `(user_name, id_string)` candidate until one decrypts the file
/// (the Mac branch, which enumerates many machine `IDString`s).
pub fn decrypt_kinf_candidates(
    data: &[u8],
    platform: Platform,
    user_name: &[u8],
    id_strings: &[Vec<u8>],
) -> Result<KindleDb> {
    let mut last = KeyError::NotFound("no IDString candidates supplied".into());
    for id in id_strings {
        match decrypt_kinf(data, platform, user_name, id) {
            Ok(db) => return Ok(db),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// `{ encodeHash(name, testMap8): name }` for the known key names. Built once
/// (the map is the same for every file and every IDString candidate) and shared,
/// so `decrypt_kinf_candidates` doesn't recompute 22 MD5 hashes per candidate.
static NAME_HASH_MAP: LazyLock<std::collections::HashMap<Vec<u8>, &'static str>> =
    LazyLock::new(|| {
        NAMES
            .iter()
            .map(|&name| (encode_hash(name.as_bytes(), TESTMAP8), name))
            .collect()
    });

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic `.kinf` file so the whole container + version pipeline
    /// can be exercised offline. `values` are (name, cleartext) pairs.
    fn synth_kinf(
        version: u32,
        build: u64,
        guid: &[u8],
        platform: Platform,
        user: &[u8],
        id: &[u8],
        values: &[(&str, &[u8])],
    ) -> Vec<u8> {
        let charmap5 = platform.charmap5();

        // --- header: AES-256-CBC(encode^-1) of the [Version][Build][Guid] text.
        let mut hdr_txt = format!("[Version:{version}][Build:{build}][Cksum:AB]").into_bytes();
        hdr_txt.extend_from_slice(b"[Guid:");
        hdr_txt.extend_from_slice(guid);
        hdr_txt.push(b']');
        while hdr_txt.len() % 16 != 0 {
            hdr_txt.push(b' ');
        }
        let key_iv = kdf::pbkdf2_sha1(HEADER_PASSWORD, HEADER_SALT, 0x80, 0x100);
        let hdr_ct = aes::cbc_encrypt(&key_iv[0..32], &key_iv[32..48], &hdr_txt).unwrap();
        let header_blob = encode(&hdr_ct, CHARMAP1);

        // --- per-value key material mirrors Decryptor::build.
        let mut records: Vec<Vec<u8>> = vec![header_blob];
        for (name, value) in values {
            let framed = encrypt_value(version, build, guid, platform, user, id, value);
            // Rotate right by noffset so decrypt's left-rotation realigns it.
            let on_disk = rotate_right(&framed);

            let keyhash = encode_hash(name.as_bytes(), TESTMAP8);
            // item = keyhash ++ encode(":1", charmap5); decode(item[34:]) == "1".
            let mut item = keyhash;
            item.extend_from_slice(&encode(b":1", charmap5));
            records.push(item);
            records.push(on_disk);
        }

        let mut out = records.join(&b'/');
        out.push(b'/');
        out
    }

    fn encrypt_value(
        version: u32,
        build: u64,
        guid: &[u8],
        platform: Platform,
        user: &[u8],
        id: &[u8],
        value: &[u8],
    ) -> Vec<u8> {
        let mut sp = Vec::new();
        sp.extend_from_slice(user);
        sp.extend_from_slice(PASSWORD_SEP);
        sp.extend_from_slice(id);
        match version {
            5 => {
                let charmap2 = platform.charmap2();
                let mut entropy = (0x2df * build).to_string().into_bytes();
                entropy.extend_from_slice(guid);
                let passwd = encode(&digest::sha256(&sp), charmap2);
                let key_iv = kdf::pbkdf2_sha1(&passwd, &entropy, 0x800, 0x400);
                // plaintext under AES = encode(value, charmap2), zero-padded to a
                // block. decode() halts at the first 0x00 (not a map symbol), so
                // the padding vanishes and the exact value is recovered.
                let mut pt = encode(value, charmap2);
                while pt.len() % 16 != 0 {
                    pt.push(0x00);
                }
                let ct = aes::cbc_encrypt(&key_iv[0..32], &key_iv[32..48], &pt).unwrap();
                encode(&ct, TESTMAP8)
            }
            6 => {
                let charmap5 = platform.charmap5();
                let mut salt = (0x6d8 * build).to_string().into_bytes();
                salt.extend_from_slice(guid);
                let passwd = encode(&digest::sha256(&sp), charmap5);
                let key = kdf::pbkdf2_sha1(&passwd, &salt, 10000, 0x400)[..32].to_vec();
                let iv12 = [0x11u8; 12];
                let mut iv = [0u8; 16];
                iv[..12].copy_from_slice(&iv12);
                iv[15] = 0x02;
                let plain = encode(value, charmap5);
                let ct = aes::ctr_apply(&key, &iv, &plain).unwrap();
                let mut iv_ct = iv12.to_vec();
                iv_ct.extend_from_slice(&ct);
                encode(&iv_ct, TESTMAP8)
            }
            _ => unreachable!(),
        }
    }

    fn rotate_right(framed: &[u8]) -> Vec<u8> {
        let len = framed.len();
        let noffset = match super::super::obfuscation::largest_prime(len / 3) {
            Some(p) => len - p,
            None => return framed.to_vec(),
        };
        let split = len - noffset;
        let mut out = Vec::with_capacity(len);
        out.extend_from_slice(&framed[split..]);
        out.extend_from_slice(&framed[..split]);
        out
    }

    #[test]
    fn v6_synthesized_record_round_trips() {
        let user = b"alice";
        let id = b"9999999999";
        let guid = b"{0123abcd-ef01-2345-6789-abcdef012345}";
        let values: &[(&str, &[u8])] = &[
            ("kindle.account.tokens", b"0123456789abcdef0123456789abcdef"),
            ("MazamaRandomNumber", b"cafebabecafebabe"),
            ("kindle.cookie.item", b"deadbeef"),
            ("login", b"alice@example.com"),
            ("kindle.key.item", b"1122334455"),
            ("kindle.name.info", b"Alice"),
            ("DSN", b"aabbccddeeff"),
        ];
        let file = synth_kinf(6, 1234, guid, Platform::Pc, user, id, values);

        let db = decrypt_kinf(&file, Platform::Pc, user, id).expect("v6 decrypt");
        for (name, value) in values {
            assert_eq!(db.get(*name), Some(&hex::encode(value)), "value for {name}");
        }
        // Bookkeeping keys are added when the file decrypts.
        assert_eq!(db.get("IDString"), Some(&hex::encode(id)));
        assert_eq!(db.get("UserName"), Some(&hex::encode(user)));
    }

    #[test]
    fn v5_mac_synthesized_record_round_trips() {
        let user = b"bob";
        let id = b"001122334455";
        let guid = b"{fedcba98-7654-3210-fedc-ba9876543210}";
        let values: &[(&str, &[u8])] = &[
            ("kindle.account.tokens", b"feedfacefeedface"),
            ("MazamaRandomNumber", b"0011223344556677"),
            ("SerialNumber", b"B001A2B3C4D5E6F7"),
            ("UsernameHash", b"99aabbcc"),
            ("kindle.key.item", b"5566778899"),
            ("login", b"bob@example.net"),
            ("DSN", b"1234abcd5678"),
        ];
        let file = synth_kinf(5, 4321, guid, Platform::Mac, user, id, values);

        let db = decrypt_kinf(&file, Platform::Mac, user, id).expect("v5 mac decrypt");
        for (name, value) in values {
            assert_eq!(db.get(*name), Some(&hex::encode(value)), "value for {name}");
        }
    }

    #[test]
    fn wrong_id_string_fails_to_decrypt() {
        let user = b"alice";
        let guid = b"{0123abcd-ef01-2345-6789-abcdef012345}";
        let values: &[(&str, &[u8])] = &[
            ("kindle.account.tokens", b"0123456789abcdef"),
            ("MazamaRandomNumber", b"cafebabecafebabe"),
            ("kindle.cookie.item", b"deadbeef"),
            ("login", b"alice@example.com"),
            ("kindle.key.item", b"1122334455"),
            ("kindle.name.info", b"Alice"),
            ("DSN", b"aabbccddeeff"),
        ];
        let file = synth_kinf(6, 1234, guid, Platform::Pc, user, b"9999999999", values);
        assert!(decrypt_kinf(&file, Platform::Pc, user, b"0000000000").is_err());
    }

    #[test]
    fn windows_v5_is_unsupported_offline() {
        // A header claiming v5 on PC must surface Unsupported, not panic.
        let guid = b"{0123abcd-ef01-2345-6789-abcdef012345}";
        // Build a v5 PC header only (no records needed to hit the branch).
        let file = synth_kinf(5, 1234, guid, Platform::Pc, b"x", b"y", &[]);
        match decrypt_kinf(&file, Platform::Pc, b"x", b"y") {
            Err(KeyError::Unsupported(_)) => {}
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn candidates_selects_the_working_id_string() {
        let user = b"carol";
        let good = b"deadbeefcafe".to_vec();
        let guid = b"{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}";
        let values: &[(&str, &[u8])] = &[
            ("kindle.account.tokens", b"0123456789abcdef"),
            ("MazamaRandomNumber", b"1111222233334444"),
            ("kindle.cookie.item", b"55667788"),
            ("login", b"carol@example.org"),
            ("kindle.key.item", b"99aabbccdd"),
            ("kindle.name.info", b"Carol"),
            ("DSN", b"eeff00112233"),
        ];
        let file = synth_kinf(6, 7777, guid, Platform::Mac, user, &good, values);
        let candidates = vec![b"wrong-one".to_vec(), b"also-wrong".to_vec(), good.clone()];
        let db = decrypt_kinf_candidates(&file, Platform::Mac, user, &candidates).unwrap();
        assert_eq!(db.get("DSN"), Some(&hex::encode(b"eeff00112233")));
    }
}
