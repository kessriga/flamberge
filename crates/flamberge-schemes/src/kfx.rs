//! KFX / KDF DRM removal via Amazon ION.
//!
//! Flow (§3): unzip → find DRMION + voucher members by magic → split PID into
//! (dsn, secret) → build `shared`, `obfuscate`, HMAC-SHA256 → AES-256-CBC unwrap
//! voucher → extract 16-byte content key → AES-128-CBC decrypt pages (+ LZMA).
//! Ported from `ion.py` (`DrmIon`, `DrmIonVoucher`) and `kfxdedrm.py`.
//! Reference: `docs/DEDRM_SCHEMES.md` §3.

use std::collections::BTreeMap;
use std::io::Cursor;

use flamberge_crypto::{aes, digest, kdf};
use flamberge_formats::ion::{BinaryIonParser, TypeId};
use flamberge_formats::kfx_zip::{self, KfxZip};

use crate::{DecryptedBook, KeyStore, Result, SchemeError};

/// The PID length splits into `(dsn_len, secret_len)`, tried in order; the first
/// whose sum equals the PID length is used (§3.3, `kfxdedrm.py`).
const PID_SPLITS: [(usize, usize); 6] = [(0, 0), (16, 0), (16, 40), (32, 40), (40, 0), (40, 40)];

/// A `.kfx-zip` is a plain zip; membership is confirmed later by finding a DRMION
/// member inside.
pub fn detect(data: &[u8]) -> bool {
    data.starts_with(b"PK\x03\x04")
}

/// Remove KFX DRM: locate the DRMION + voucher members, unwrap the voucher with a
/// candidate PID, decrypt every DRMION member, and repackage the zip.
pub fn decrypt(input: &[u8], keys: &KeyStore) -> Result<DecryptedBook> {
    if !detect(input) {
        return Err(SchemeError::NotThisScheme);
    }

    let container = KfxZip::parse(input)?;
    if container.drmion_members.is_empty() {
        // A plain zip with no encrypted DRMION member is not a KFX DRM book.
        return Err(SchemeError::NotThisScheme);
    }

    let voucher_bytes = container.voucher.ok_or_else(|| {
        SchemeError::Format(flamberge_formats::FormatError::Invalid(
            "KFX archive has an encrypted DRMION member but no DRM voucher".into(),
        ))
    })?;

    let voucher = unwrap_voucher_with_candidates(&voucher_bytes, keys)?;
    if voucher.license_type != "Purchase" {
        return Err(SchemeError::NotPurchased(voucher.license_type));
    }

    let mut replacements = BTreeMap::new();
    for (name, payload) in &container.drmion_members {
        let decrypted = decrypt_drmion(payload, &voucher.content_key)?;
        replacements.insert(name.clone(), decrypted);
    }

    let data = kfx_zip::repackage(input, &replacements)?;
    Ok(DecryptedBook {
        data,
        extension: "kfx-zip".to_string(),
        title: None,
    })
}

/// The unwrapped voucher: the 16-byte content key plus the license type.
struct Voucher {
    content_key: Vec<u8>,
    license_type: String,
}

/// Try each candidate PID (`""` first, then explicit PIDs and serials) against
/// the voucher until one unwraps it. A wrong PID fails the PKCS#7 check and the
/// next candidate is tried (§3.3, `kfxdedrm.py::decrypt_voucher`).
fn unwrap_voucher_with_candidates(envelope: &[u8], keys: &KeyStore) -> Result<Voucher> {
    // Parse the (PID-independent) envelope once. A structural/parse failure here
    // is a real error — surface it via `?` rather than letting the candidate loop
    // mask it as `NoKeyWorked`, which would misdirect the user to hunt for a key.
    let parsed = parse_voucher_envelope(envelope)?;
    for pid in candidate_pids(keys) {
        let bytes = pid.as_bytes();
        // Pick the first split whose lengths sum to this PID's length.
        let Some(&(dsn_len, _)) = PID_SPLITS.iter().find(|(d, s)| d + s == bytes.len()) else {
            continue; // no documented split matches this PID length; skip it
        };
        let (dsn, secret) = bytes.split_at(dsn_len);
        if let Ok(v) = unwrap_with(&parsed, dsn, secret) {
            return Ok(v);
        }
    }
    Err(SchemeError::NoKeyWorked)
}

/// Candidate PID strings: the empty PID first (`kfxdedrm.py` prepends `''`), then
/// explicit PIDs and device serials, de-duplicated with order preserved.
fn candidate_pids(keys: &KeyStore) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for pid in std::iter::once(String::new())
        .chain(keys.pids.iter().cloned())
        .chain(keys.serials.iter().cloned())
    {
        if seen.insert(pid.clone()) {
            out.push(pid);
        }
    }
    out
}

/// The PID-independent contents of a `VoucherEnvelope`: everything needed to
/// derive the KEK and unwrap the inner voucher once a `(dsn, secret)` is chosen.
struct ParsedVoucher {
    version: i64,
    enc_algorithm: String,
    enc_transformation: String,
    hash_algorithm: String,
    /// Lock parameters (`ACCOUNT_SECRET` / `CLIENT_ID`), pre-sorted (§3.3).
    lock_parameters: Vec<String>,
    cipher_iv: Vec<u8>,
    cipher_text: Vec<u8>,
    license_type: String,
}

/// Parse a `VoucherEnvelope` struct and its inner voucher (PID-independent). A
/// malformed envelope surfaces here as a real error rather than being masked as
/// "wrong PID". Port of `DrmIonVoucher.parse`/`parsevoucher` (§3.3).
fn parse_voucher_envelope(envelope: &[u8]) -> Result<ParsedVoucher> {
    let mut env = new_parser(envelope);
    env.reset();

    if env.next()? != Some(TypeId::Struct)
        || !env
            .type_name()
            .starts_with("com.amazon.drm.VoucherEnvelope@")
    {
        return Err(invalid("expected a VoucherEnvelope struct"));
    }
    let version = parse_envelope_version(&env.type_name())?;

    let mut enc_algorithm = String::new();
    let mut enc_transformation = String::new();
    let mut hash_algorithm = String::new();
    let mut lock_parameters: Vec<String> = Vec::new();
    let mut inner_voucher: Option<Vec<u8>> = None;

    env.step_in()?;
    while env.next()?.is_some() {
        let field = env.field_name();
        if field == "voucher" {
            inner_voucher = env.lob_value()?;
            continue;
        }
        if field != "strategy" {
            continue;
        }
        if env.type_name() != "com.amazon.drm.PIDv3@1.0" {
            return Err(invalid("unknown voucher strategy"));
        }
        env.step_in()?;
        while env.next()?.is_some() {
            match env.field_name().as_str() {
                "encryption_algorithm" => enc_algorithm = env.string_value()?,
                "encryption_transformation" => enc_transformation = env.string_value()?,
                "hashing_algorithm" => hash_algorithm = env.string_value()?,
                "lock_parameters" => {
                    env.step_in()?;
                    while let Some(tid) = env.next()? {
                        if tid != TypeId::String {
                            return Err(invalid("lock_parameters must be strings"));
                        }
                        lock_parameters.push(env.string_value()?);
                    }
                    env.step_out()?;
                }
                _ => {}
            }
        }
        env.step_out()?;
    }
    env.step_out()?;

    let inner_voucher = inner_voucher.ok_or_else(|| invalid("voucher envelope has no voucher"))?;
    let (cipher_iv, cipher_text, license_type) = parse_inner_voucher(&inner_voucher)?;
    if cipher_iv.len() < 16 {
        return Err(invalid("voucher cipher_iv is shorter than 16 bytes"));
    }
    lock_parameters.sort();

    Ok(ParsedVoucher {
        version,
        enc_algorithm,
        enc_transformation,
        hash_algorithm,
        lock_parameters,
        cipher_iv,
        cipher_text,
        license_type,
    })
}

/// Derive the KEK from `(dsn, secret)`, AES-256-CBC unwrap the voucher, and
/// extract the 16-byte content key. A wrong PID fails the PKCS#7 check here, so
/// the caller treats `Err` as "try the next candidate". Port of
/// `DrmIonVoucher.decryptvoucher` (§3.3).
fn unwrap_with(pv: &ParsedVoucher, dsn: &[u8], secret: &[u8]) -> Result<Voucher> {
    // Build the shared secret from the sorted lock parameters, obfuscate it, and
    // derive the AES-256 KEK (§3.3).
    let mut shared = format!(
        "PIDv3{}{}{}",
        pv.enc_algorithm, pv.enc_transformation, pv.hash_algorithm
    )
    .into_bytes();
    for param in &pv.lock_parameters {
        match param.as_str() {
            "ACCOUNT_SECRET" => {
                shared.extend_from_slice(b"ACCOUNT_SECRET");
                shared.extend_from_slice(secret);
            }
            "CLIENT_ID" => {
                shared.extend_from_slice(b"CLIENT_ID");
                shared.extend_from_slice(dsn);
            }
            other => return Err(invalid(&format!("unknown lock parameter: {other}"))),
        }
    }

    let shared_secret = obfuscate(&shared, pv.version)?;
    let kek = kdf::hmac_sha256(&shared_secret, b"PIDv3");
    // AES-256-CBC (32-byte KEK), then strip PKCS#7. A wrong PID surfaces here.
    let plain = aes::cbc_decrypt(&kek, &pv.cipher_iv[..16], &pv.cipher_text)?;
    let plain = kdf::pkcs7_unpad(&plain, 16)?;

    let content_key = extract_content_key(&plain)?;
    Ok(Voucher {
        content_key,
        license_type: pv.license_type.clone(),
    })
}

/// Test-only combiner: parse the envelope then unwrap it with a single
/// `(dsn, secret)` pair.
#[cfg(test)]
fn unwrap_voucher(envelope: &[u8], dsn: &[u8], secret: &[u8]) -> Result<Voucher> {
    unwrap_with(&parse_voucher_envelope(envelope)?, dsn, secret)
}

/// Parse the inner `com.amazon.drm.Voucher@1.0` struct into
/// `(cipher_iv, cipher_text, license_type)`.
fn parse_inner_voucher(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>, String)> {
    let mut v = new_parser(bytes);
    if v.next()? != Some(TypeId::Struct) || v.type_name() != "com.amazon.drm.Voucher@1.0" {
        return Err(invalid("expected a Voucher struct"));
    }

    let mut cipher_iv = Vec::new();
    let mut cipher_text = Vec::new();
    let mut license_type = String::from("Unknown");

    v.step_in()?;
    while v.next()?.is_some() {
        match v.field_name().as_str() {
            "cipher_iv" => cipher_iv = v.lob_value()?.unwrap_or_default(),
            "cipher_text" => cipher_text = v.lob_value()?.unwrap_or_default(),
            "license" => {
                if v.type_name() != "com.amazon.drm.License@1.0" {
                    return Err(invalid("unknown license type container"));
                }
                v.step_in()?;
                while v.next()?.is_some() {
                    if v.field_name() == "license_type" {
                        license_type = v.string_value()?;
                    }
                }
                v.step_out()?;
            }
            _ => {}
        }
    }
    v.step_out()?;

    Ok((cipher_iv, cipher_text, license_type))
}

/// From the decrypted voucher ION (a `KeySet` list), find the `SecretKey`
/// (`algorithm=="AES"`, `format=="RAW"`) and return its `encoded` bytes.
fn extract_content_key(plain: &[u8]) -> Result<Vec<u8>> {
    let mut k = new_parser(plain);
    if k.next()? != Some(TypeId::List) || k.type_name() != "com.amazon.drm.KeySet@1.0" {
        return Err(invalid("expected a KeySet list"));
    }

    let mut content_key: Option<Vec<u8>> = None;
    k.step_in()?;
    while k.next()?.is_some() {
        if k.type_name() != "com.amazon.drm.SecretKey@1.0" {
            continue;
        }
        k.step_in()?;
        while k.next()?.is_some() {
            match k.field_name().as_str() {
                "algorithm" => {
                    if k.string_value()? != "AES" {
                        return Err(invalid("unexpected key algorithm (want AES)"));
                    }
                }
                "format" => {
                    if k.string_value()? != "RAW" {
                        return Err(invalid("unexpected key format (want RAW)"));
                    }
                }
                "encoded" => content_key = k.lob_value()?,
                _ => {}
            }
        }
        k.step_out()?;
        break;
    }
    k.step_out()?;

    content_key.ok_or_else(|| invalid("voucher KeySet has no encoded content key"))
}

/// Decrypt one DRMION member (8+8 already stripped) into concatenated page bytes.
/// Port of `DrmIon.parse` (§3.4). `content_key`'s first 16 bytes are the AES-128
/// page key.
fn decrypt_drmion(payload: &[u8], content_key: &[u8]) -> Result<Vec<u8>> {
    let mut ion = new_parser(payload);
    ion.reset();

    if ion.next()? != Some(TypeId::Symbol) || ion.type_name() != "doctype" {
        return Err(invalid("DRMION: expected a doctype symbol"));
    }
    match ion.next()? {
        Some(TypeId::List)
            if matches!(
                ion.type_name().as_str(),
                "com.amazon.drm.Envelope@1.0" | "com.amazon.drm.Envelope@2.0"
            ) => {}
        _ => return Err(invalid("DRMION: expected an Envelope list")),
    }

    let mut out = Vec::new();
    loop {
        if ion.type_name() == "enddoc" {
            break;
        }
        ion.step_in()?;
        while ion.next()?.is_some() {
            process_envelope_member(&mut ion, content_key, &mut out)?;
        }
        ion.step_out()?;
        if ion.next()?.is_none() {
            break;
        }
    }

    Ok(out)
}

/// Handle one member of the DRMION `Envelope` list: metadata (skipped), an
/// encrypted page (decrypt + optional decompress), or plaintext (copy + optional
/// decompress).
fn process_envelope_member(
    ion: &mut BinaryIonParser,
    content_key: &[u8],
    out: &mut Vec<u8>,
) -> Result<()> {
    match ion.type_name().as_str() {
        "com.amazon.drm.EnvelopeMetadata@1.0" | "com.amazon.drm.EnvelopeMetadata@2.0" => {
            // Names the voucher; we already hold its content key, so just skip.
            ion.step_in()?;
            while ion.next()?.is_some() {}
            ion.step_out()?;
        }
        "com.amazon.drm.EncryptedPage@1.0" | "com.amazon.drm.EncryptedPage@2.0" => {
            let mut compressed = false;
            let mut cipher_text: Option<Vec<u8>> = None;
            let mut cipher_iv: Option<Vec<u8>> = None;
            ion.step_in()?;
            while ion.next()?.is_some() {
                if ion.type_name() == "com.amazon.drm.Compressed@1.0" {
                    compressed = true;
                }
                match ion.field_name().as_str() {
                    "cipher_text" => cipher_text = ion.lob_value()?,
                    "cipher_iv" => cipher_iv = ion.lob_value()?,
                    _ => {}
                }
            }
            ion.step_out()?;
            if let (Some(ct), Some(iv)) = (cipher_text, cipher_iv) {
                process_page(&ct, Some(&iv), content_key, true, compressed, out)?;
            }
        }
        "com.amazon.drm.PlainText@1.0" | "com.amazon.drm.PlainText@2.0" => {
            let mut compressed = false;
            let mut data: Option<Vec<u8>> = None;
            ion.step_in()?;
            while ion.next()?.is_some() {
                if ion.type_name() == "com.amazon.drm.Compressed@1.0" {
                    compressed = true;
                }
                if ion.field_name() == "data" {
                    data = ion.lob_value()?;
                }
            }
            ion.step_out()?;
            if let Some(d) = data {
                process_page(&d, None, content_key, false, compressed, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Decrypt (AES-128-CBC + PKCS#7) and/or LZMA-decompress a single page, appending
/// the result to `out` (§3.4, `DrmIon.processpage`).
fn process_page(
    ct: &[u8],
    civ: Option<&[u8]>,
    content_key: &[u8],
    decrypt: bool,
    decompress: bool,
    out: &mut Vec<u8>,
) -> Result<()> {
    let msg = if decrypt {
        if content_key.len() < 16 {
            return Err(invalid("content key is shorter than 16 bytes"));
        }
        let iv = civ.ok_or_else(|| invalid("encrypted page has no cipher_iv"))?;
        if iv.len() < 16 {
            return Err(invalid("page cipher_iv is shorter than 16 bytes"));
        }
        let dec = aes::cbc_decrypt(&content_key[..16], &iv[..16], ct)?;
        kdf::pkcs7_unpad(&dec, 16)?
    } else {
        ct.to_vec()
    };

    if !decompress {
        out.extend_from_slice(&msg);
        return Ok(());
    }

    // Compressed pages: a leading 0x00 "UseFilter" byte then an LZMA-alone stream.
    if msg.first() != Some(&0) {
        return Err(invalid("compressed page: unsupported LZMA UseFilter byte"));
    }
    let mut reader = Cursor::new(&msg[1..]);
    let mut decompressed = Vec::new();
    lzma_rs::lzma_decompress(&mut reader, &mut decompressed)
        .map_err(|e| invalid(&format!("LZMA decompress failed: {e}")))?;
    out.extend_from_slice(&decompressed);
    Ok(())
}

/// Obfuscate the shared secret for the given `VoucherEnvelope` version (§3.3).
/// Version 1 is identity; otherwise permute the (zero-padded) secret and XOR with
/// `SHA256(word)[index % 16]`. Port of `ion.py::obfuscate`.
fn obfuscate(secret: &[u8], version: i64) -> Result<Vec<u8>> {
    if version == 1 {
        return Ok(secret.to_vec());
    }
    let (magic, word) =
        obfuscation_entry(version).ok_or_else(|| invalid("unknown VoucherEnvelope version"))?;

    let mut secret = secret.to_vec();
    if secret.len() % magic != 0 {
        secret.resize(secret.len() + (magic - secret.len() % magic), 0);
    }
    if secret.is_empty() {
        return Ok(secret);
    }

    let rows = secret.len() / magic;
    let word_hash = digest::sha256(word);
    let mut obfuscated = vec![0u8; secret.len()];
    for (i, &byte) in secret.iter().enumerate() {
        let index = i / rows + magic * (i % rows);
        obfuscated[index] = byte ^ word_hash[index % 16];
    }
    Ok(obfuscated)
}

/// `(magic, word)` for a `VoucherEnvelope` version, ported byte-for-byte from
/// `ion.py::OBFUSCATION_TABLE`. Version 1 (identity) is handled before this call,
/// so its `magic` of 0 is never used. `V9708`'s word preserves the reference's
/// corrupted bytes verbatim so behavior matches the original exactly.
fn obfuscation_entry(version: i64) -> Option<(usize, &'static [u8])> {
    let entry: (usize, &'static [u8]) = match version {
        1 => (0, b""),
        2 => (5, b"Antidisestablishmentarianism"),
        3 => (8, b"Floccinaucinihilipilification"),
        4 => (7, b">\x14\x0c\x12\x10-\x13&\x18U\x1d\x05Rlt\x03!\x19\x1b\x13\x04]Y\x19,\x09\x1b"),
        5 => (
            6,
            b"~\x18~\x16J\\\x18\x10\x05\x0b\x07\x09\x0cZ\x0d|\x1c\x15\x1d\x11>,\x1b\x0e\x03\"4\x1b\x01",
        ),
        6 => (9, b"3h\x055\x03[^>\x19\x1c\x08\x1b\x0dtm4\x02Rp\x0c\x16B\x0a"),
        7 => (5, b"\x10\x1bJ\x18\x0ah!\x10\"\x03>Z'\x0d\x01]W\x06\x1c\x1e?\x0f\x13"),
        8 => (9, b"K\x0c6\x1d\x1a\x17pO}Rk\x1d'w1^\x1f$\x1c{C\x02Q\x06\x1d`"),
        9 => (
            5,
            b"X.\x0eW\x1c*K\x12\x12\x09\x0a\x0a\x17Wx\x01\x02Yf\x0f\x18\x1bVXPi\x01",
        ),
        10 => (
            7,
            b"z3\x0a\x039\x12\x13`\x06=v,\x02MTK\x1e%}L\x1c\x1f\x15\x0c\x11\x02\x0c\x0a8\x17p",
        ),
        11 => (5, b"L=\x0ahVm\x07go\x0a6\x14\x06\x16L\x0d\x02\x0b\x0c\x1b\x04#p\x09"),
        12 => (6, b",n\x1d\x0dl\x13\x1c\x13\x16p\x14\x07U\x0c\x1f\x19w\x16\x16\x1d5T"),
        13 => (7, b"I\x05\x09\x08\x03r)\x01$N\x0fr3n\x0b062D\x0f\x13"),
        14 => (
            5,
            b"\x03\x02\x1c9\x19\x15\x15q\x1057\x08\x16\x0cF\x1b.Fw\x01\x12\x03\x13\x02\x17S'hk6",
        ),
        15 => (
            10,
            b"&,4B\x1dcI\x0bU\x03I\x07\x04\x1c\x09\x05c\x07%ws\x0cj\x09\x1a\x08\x0f",
        ),
        16 => (10, b"\x06\x18`h,b><\x06PqR\x02Zc\x034\x0a\x16\x1e\x18\x06#e"),
        17 => (
            7,
            b"y\x0d\x12\x08fw.[\x02\x09\x0a\x13\x11\x0c\x11b\x1e8L\x10(\x13<Jx6c\x0f",
        ),
        18 => (
            7,
            b"I\x0b\x0e,\x19\x1aIa\x10s\x19g\\\x1b\x11!\x18yf\x0f\x09\x1d7[bSp\x03",
        ),
        19 => (
            5,
            b"\x0a6>)N\x02\x188\x016s\x13\x14\x1b\x16jeN\x0a\x146\x04\x18\x1c\x0c\x19\x1f,\x02]",
        ),
        20 => (8, b"_\x0d\x01\x12]\\\x14*\x17i\x14\x0d\x09!\x1e,~hZ\x12jK\x17\x1e*1"),
        21 => (
            7,
            b"e\x1d\x19|\x09y\x1di|N\x13\x0e\x04\x1bj<h\x13\x15k\x12\x08=\x1f\x16~\x13l",
        ),
        22 => (
            8,
            b"?\x17yi$k7Pc\x09Eo\x0c\x07\x07\x09\x1f,*i\x12\x0cI0\x10I\x1a?2\x04",
        ),
        23 => (8, b"\x16+db\x13\x04\x18\x0dc%\x14\x17\x0f\x13F\x0c[\x099\x1ay\x01\x1eH"),
        24 => (6, b"|6\\\x1a\x0d\x10\x0aP\x07\x0fu\x1f\x09,\x0dr`uv\\~55\x11]N"),
        25 => (
            9,
            b"\x07\x14w\x1e,^y\x01:\x08\x07\x1fr\x09U#j\x16\x12\x1eB\x04\x16=\x06fZ\x07\x02\x06",
        ),
        26 => (6, b"\x03IL\x1e\"K\x1f\x0f\x1fp0\x01`X\x02z0`\x03\x0eN\x07"),
        27 => (
            7,
            b"Xk\x10y\x02\x18\x10\x17\x1d,\x0e\x05e\x10\x15\"e\x0fh(\x06s\x1c\x08I\x0c\x1b\x0e",
        ),
        28 => (10, b"6P\x1bs\x0f\x06V.\x1cM\x14\x02\x0a\x1b\x07{P0:\x18zaU\x05"),
        9708 => (
            5,
            b"\x1diIm\x08a\x17\x1e!am\x1d\x1aQ.\x16!\x06*\\}x04\x11\x09\x06\x04?",
        ),
        1031 => (8, b"Antidisestablishmentarianism"),
        2069 => (7, b"Floccinaucinihilipilification"),
        9041 => (6, b">\x14\x0c\x12\x10-\x13&\x18U\x1d\x05Rlt\x03!\x19\x1b\x13\x04]Y\x19,\x09\x1b"),
        3646 => (
            9,
            b"~\x18~\x16J\\\x18\x10\x05\x0b\x07\x09\x0cZ\x0d|\x1c\x15\x1d\x11>,\x1b\x0e\x03\"4\x1b\x01",
        ),
        6052 => (5, b"3h\x055\x03[^>\x19\x1c\x08\x1b\x0dtm4\x02Rp\x0c\x16B\x0a"),
        9479 => (9, b"\x10\x1bJ\x18\x0ah!\x10\"\x03>Z'\x0d\x01]W\x06\x1c\x1e?\x0f\x13"),
        9888 => (5, b"K\x0c6\x1d\x1a\x17pO}Rk\x1d'w1^\x1f$\x1c{C\x02Q\x06\x1d`"),
        4648 => (
            7,
            b"X.\x0eW\x1c*K\x12\x12\x09\x0a\x0a\x17Wx\x01\x02Yf\x0f\x18\x1bVXPi\x01",
        ),
        5683 => (
            5,
            b"z3\x0a\x039\x12\x13`\x06=v,\x02MTK\x1e%}L\x1c\x1f\x15\x0c\x11\x02\x0c\x0a8\x17p",
        ),
        _ => return None,
    };
    Some(entry)
}

/// Parse the numeric version out of a `com.amazon.drm.VoucherEnvelope@<n>.0`
/// type name (drops the trailing `.0`, mirroring `ion.py`'s `[1][:-2]`).
fn parse_envelope_version(type_name: &str) -> Result<i64> {
    let after_at = type_name
        .split('@')
        .nth(1)
        .ok_or_else(|| invalid("VoucherEnvelope type name has no @version"))?;
    let trimmed = &after_at[..after_at.len().saturating_sub(2)];
    trimmed
        .parse::<i64>()
        .map_err(|_| invalid("VoucherEnvelope version is not an integer"))
}

/// Build a parser over `bytes` with the `ProtectedData` shared symbol table
/// pre-seeded (every KFX ION stream needs it).
fn new_parser(bytes: &[u8]) -> BinaryIonParser<'_> {
    let mut p = BinaryIonParser::new(bytes);
    p.add_protected_data_table();
    p
}

fn invalid(msg: &str) -> SchemeError {
    SchemeError::Format(flamberge_formats::FormatError::Invalid(msg.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flamberge_formats::ion::protected_data_symbols;

    // --- Minimal ION encoder (mirrors the helpers in `ion.rs` tests) so we can
    // synthesize vouchers and pages that the real parser reads back. ---

    fn varuint(mut n: u64) -> Vec<u8> {
        let mut groups = vec![(n & 0x7F) as u8];
        n >>= 7;
        while n > 0 {
            groups.push((n & 0x7F) as u8);
            n >>= 7;
        }
        groups.reverse();
        let last = groups.len() - 1;
        groups[last] |= 0x80;
        groups
    }

    fn typed(tid: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let len = body.len();
        let var_len = len >= 14 || (tid == 0xD && len == 1);
        if var_len {
            out.push((tid << 4) | 0x0E);
            out.extend(varuint(len as u64));
        } else {
            out.push((tid << 4) | (len as u8));
        }
        out.extend_from_slice(body);
        out
    }

    fn e_string(s: &str) -> Vec<u8> {
        typed(0x8, s.as_bytes())
    }
    fn e_blob(b: &[u8]) -> Vec<u8> {
        typed(0xA, b)
    }
    fn e_symbol(sid: u64) -> Vec<u8> {
        let mut m = Vec::new();
        let mut n = sid;
        if n == 0 {
            m.push(0);
        }
        while n > 0 {
            m.push((n & 0xFF) as u8);
            n >>= 8;
        }
        m.reverse();
        typed(0x7, &m)
    }
    fn e_posint(mut n: u64) -> Vec<u8> {
        if n == 0 {
            return typed(0x2, &[]);
        }
        let mut bytes = Vec::new();
        while n > 0 {
            bytes.push((n & 0xFF) as u8);
            n >>= 8;
        }
        bytes.reverse();
        typed(0x2, &bytes)
    }
    fn e_field(sid: u64, val: &[u8]) -> Vec<u8> {
        let mut out = varuint(sid);
        out.extend_from_slice(val);
        out
    }
    fn e_struct(fields: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        for f in fields {
            body.extend_from_slice(f);
        }
        typed(0xD, &body)
    }
    fn e_list(items: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        for i in items {
            body.extend_from_slice(i);
        }
        typed(0xB, &body)
    }
    fn e_annot(sids: &[u64], val: &[u8]) -> Vec<u8> {
        let mut sid_bytes = Vec::new();
        for &s in sids {
            sid_bytes.extend(varuint(s));
        }
        let mut body = varuint(sid_bytes.len() as u64);
        body.extend(sid_bytes);
        body.extend_from_slice(val);
        typed(0xE, &body)
    }
    fn bvm() -> Vec<u8> {
        vec![0xE0, 0x01, 0x00, 0xEA]
    }

    /// SID of an imported `ProtectedData` symbol (system symbols occupy 1–9).
    fn sid(name: &str) -> u64 {
        10 + protected_data_symbols()
            .iter()
            .position(|s| s == name)
            .unwrap_or_else(|| panic!("unknown symbol {name}")) as u64
    }

    /// A local symbol-table directive importing the shared `ProtectedData` table.
    fn import_directive() -> Vec<u8> {
        let syms = protected_data_symbols();
        e_annot(
            &[3], // $ion_symbol_table
            &e_struct(&[e_field(
                6, // imports
                &e_list(&[e_struct(&[
                    e_field(4, &e_string("ProtectedData")),
                    e_field(5, &e_posint(1)),
                    e_field(8, &e_posint(syms.len() as u64)),
                ])]),
            )]),
        )
    }

    fn ion_doc(value: Vec<u8>) -> Vec<u8> {
        let mut d = bvm();
        d.extend(import_directive());
        d.extend(value);
        d
    }

    fn pkcs7_pad(data: &[u8], block: usize) -> Vec<u8> {
        let pad = block - data.len() % block;
        let mut out = data.to_vec();
        out.extend(std::iter::repeat_n(pad as u8, pad));
        out
    }

    // --- obfuscate() vs. reference Python vectors ---

    #[test]
    fn obfuscate_v1_is_identity() {
        assert_eq!(obfuscate(b"hello", 1).unwrap(), b"hello");
    }

    #[test]
    fn obfuscate_matches_reference_vectors() {
        assert_eq!(
            obfuscate(b"hello world", 2).unwrap(),
            hex(b"1a10684e99e09d75c36697dfb48f5b")
        );
        assert_eq!(
            obfuscate(b"abcdefghijklmnop", 3).unwrap(),
            hex(b"5032ebbd55bd3023d591b9154adad481")
        );
        assert_eq!(
            obfuscate(b"PIDv3CLIENT_IDabcdef", 28).unwrap(),
            hex(b"48c51f5e5442fbc3784303ab67dccc8f5ce34874")
        );
    }

    #[test]
    fn obfuscation_table_has_every_version() {
        for v in 2..=28 {
            assert!(obfuscation_entry(v).is_some(), "missing V{v}");
        }
        for v in [9708, 1031, 2069, 9041, 3646, 6052, 9479, 9888, 4648, 5683] {
            assert!(obfuscation_entry(v).is_some(), "missing V{v}");
        }
        assert!(obfuscation_entry(99).is_none());
    }

    fn hex(h: &[u8]) -> Vec<u8> {
        h.chunks(2)
            .map(|c| {
                let s = std::str::from_utf8(c).unwrap();
                u8::from_str_radix(s, 16).unwrap()
            })
            .collect()
    }

    // --- Voucher synthesis ---

    struct VoucherParams {
        version: i64,
        enc_algorithm: &'static str,
        enc_transformation: &'static str,
        hash_algorithm: &'static str,
        lock_parameters: Vec<&'static str>,
        dsn: Vec<u8>,
        secret: Vec<u8>,
        content_key: [u8; 16],
        license_type: &'static str,
    }

    /// Build a full `VoucherEnvelope` ION stream that unwraps to `content_key`.
    fn synthesize_voucher(p: &VoucherParams) -> Vec<u8> {
        // 1. KeySet plaintext ION carrying the content key.
        let keyset = ion_doc(e_annot(
            &[sid("com.amazon.drm.KeySet@1.0")],
            &e_list(&[e_annot(
                &[sid("com.amazon.drm.SecretKey@1.0")],
                &e_struct(&[
                    e_field(sid("algorithm"), &e_string("AES")),
                    e_field(sid("format"), &e_string("RAW")),
                    e_field(sid("encoded"), &e_blob(&p.content_key)),
                ]),
            )]),
        ));

        // 2. Derive the same KEK the decryptor will, then encrypt the KeySet.
        let mut shared = format!(
            "PIDv3{}{}{}",
            p.enc_algorithm, p.enc_transformation, p.hash_algorithm
        )
        .into_bytes();
        let mut params: Vec<&str> = p.lock_parameters.clone();
        params.sort();
        for param in &params {
            match *param {
                "ACCOUNT_SECRET" => {
                    shared.extend_from_slice(b"ACCOUNT_SECRET");
                    shared.extend_from_slice(&p.secret);
                }
                "CLIENT_ID" => {
                    shared.extend_from_slice(b"CLIENT_ID");
                    shared.extend_from_slice(&p.dsn);
                }
                _ => unreachable!(),
            }
        }
        let shared_secret = obfuscate(&shared, p.version).unwrap();
        let kek = kdf::hmac_sha256(&shared_secret, b"PIDv3");
        let iv = [0x11u8; 16];
        let cipher_text = aes::cbc_encrypt(&kek, &iv, &pkcs7_pad(&keyset, 16)).unwrap();

        // 3. Inner Voucher struct.
        let inner = ion_doc(e_annot(
            &[sid("com.amazon.drm.Voucher@1.0")],
            &e_struct(&[
                e_field(sid("cipher_iv"), &e_blob(&iv)),
                e_field(sid("cipher_text"), &e_blob(&cipher_text)),
                e_field(
                    sid("license"),
                    &e_annot(
                        &[sid("com.amazon.drm.License@1.0")],
                        &e_struct(&[e_field(sid("license_type"), &e_string(p.license_type))]),
                    ),
                ),
            ]),
        ));

        // 4. Envelope: strategy (PIDv3) + inner voucher BLOB.
        let lock_items: Vec<Vec<u8>> = params.iter().map(|s| e_string(s)).collect();
        let strategy = e_field(
            sid("strategy"),
            &e_annot(
                &[sid("com.amazon.drm.PIDv3@1.0")],
                &e_struct(&[
                    e_field(sid("encryption_algorithm"), &e_string(p.enc_algorithm)),
                    e_field(
                        sid("encryption_transformation"),
                        &e_string(p.enc_transformation),
                    ),
                    e_field(sid("hashing_algorithm"), &e_string(p.hash_algorithm)),
                    e_field(sid("lock_parameters"), &e_list(&lock_items)),
                ]),
            ),
        );
        let voucher_field = e_field(sid("voucher"), &e_blob(&inner));

        ion_doc(e_annot(
            &[sid(&format!(
                "com.amazon.drm.VoucherEnvelope@{}.0",
                p.version
            ))],
            &e_struct(&[strategy, voucher_field]),
        ))
    }

    fn default_voucher(content_key: [u8; 16]) -> VoucherParams {
        VoucherParams {
            version: 2,
            enc_algorithm: "AES",
            enc_transformation: "AES/CBC/PKCS5Padding",
            hash_algorithm: "SHA-256",
            lock_parameters: vec!["ACCOUNT_SECRET", "CLIENT_ID"],
            // 16-byte dsn + 40-byte secret => a 56-char PID, split as (16, 40).
            dsn: b"0123456789abcdef".to_vec(),
            secret: b"0123456789abcdefghijklmnopqrstuvwxyzABCD".to_vec(),
            content_key,
            license_type: "Purchase",
        }
    }

    #[test]
    fn unwrap_voucher_recovers_content_key() {
        let key = [0xABu8; 16];
        let p = default_voucher(key);
        let envelope = synthesize_voucher(&p);

        let v = unwrap_voucher(&envelope, &p.dsn, &p.secret).unwrap();
        assert_eq!(v.content_key, key);
        assert_eq!(v.license_type, "Purchase");
    }

    #[test]
    fn unwrap_voucher_wrong_secret_fails() {
        let p = default_voucher([0x01u8; 16]);
        let envelope = synthesize_voucher(&p);
        // Correct dsn, wrong account secret => wrong KEK => PKCS#7 failure.
        let wrong = b"wrong-secret-value-.....................".to_vec();
        assert!(unwrap_voucher(&envelope, &p.dsn, &wrong).is_err());
    }

    #[test]
    fn unwrap_voucher_version_1_identity() {
        let key = [0x5Au8; 16];
        let mut p = default_voucher(key);
        p.version = 1;
        p.lock_parameters = vec!["CLIENT_ID"];
        let envelope = synthesize_voucher(&p);
        let v = unwrap_voucher(&envelope, &p.dsn, &p.secret).unwrap();
        assert_eq!(v.content_key, key);
    }

    #[test]
    fn candidate_loop_tries_pids_until_one_works() {
        // Voucher locked to CLIENT_ID = a 16-char dsn, no account secret.
        let key = [0x77u8; 16];
        let mut p = default_voucher(key);
        p.lock_parameters = vec!["CLIENT_ID"];
        p.secret = Vec::new();
        let correct_dsn = "fedcba9876543210"; // 16 chars => split (16, 0)
        p.dsn = correct_dsn.as_bytes().to_vec();
        let envelope = synthesize_voucher(&p);

        let keys = KeyStore {
            pids: vec!["0000000000000000".to_string(), correct_dsn.to_string()],
            ..KeyStore::default()
        };
        let v = unwrap_voucher_with_candidates(&envelope, &keys).unwrap();
        assert_eq!(v.content_key, key);
    }

    #[test]
    fn malformed_voucher_surfaces_real_error_not_no_key_worked() {
        // A syntactically-valid ION stream that is not a VoucherEnvelope: the
        // structural failure must surface, not be masked as NoKeyWorked (which
        // would send the user hunting for a key that would never work).
        let bogus = ion_doc(e_posint(42));
        let keys = KeyStore {
            pids: vec!["0123456789abcdef".to_string()],
            ..KeyStore::default()
        };
        match unwrap_voucher_with_candidates(&bogus, &keys) {
            Err(SchemeError::NoKeyWorked) => panic!("structural error masked as NoKeyWorked"),
            Err(_) => {}
            Ok(_) => panic!("expected an error for a non-voucher stream"),
        }
    }

    #[test]
    fn candidate_loop_exhausts_and_fails() {
        let mut p = default_voucher([0x02u8; 16]);
        p.lock_parameters = vec!["CLIENT_ID"];
        p.secret = Vec::new();
        p.dsn = b"the-right-dsn-16b".to_vec();
        let envelope = synthesize_voucher(&p);

        let keys = KeyStore {
            pids: vec!["wrong-dsn-16char".to_string()],
            ..KeyStore::default()
        };
        assert!(matches!(
            unwrap_voucher_with_candidates(&envelope, &keys),
            Err(SchemeError::NoKeyWorked)
        ));
    }

    // --- Content page decryption ---

    fn encrypted_page(content_key: &[u8], plaintext: &[u8], compressed: bool) -> Vec<u8> {
        let iv = [0x22u8; 16];
        let body = if compressed {
            let mut c = vec![0u8]; // UseFilter byte
            let mut input = Cursor::new(plaintext);
            lzma_rs::lzma_compress(&mut input, &mut c).unwrap();
            c
        } else {
            plaintext.to_vec()
        };
        let ct = aes::cbc_encrypt(&content_key[..16], &iv, &pkcs7_pad(&body, 16)).unwrap();

        let mut fields = vec![
            e_field(sid("cipher_text"), &e_blob(&ct)),
            e_field(sid("cipher_iv"), &e_blob(&iv)),
        ];
        if compressed {
            fields.push(e_field(
                sid("compression_algorithm"),
                &e_annot(
                    &[sid("com.amazon.drm.Compressed@1.0")],
                    &e_symbol(sid("data")),
                ),
            ));
        }
        e_annot(
            &[sid("com.amazon.drm.EncryptedPage@1.0")],
            &e_struct(&fields),
        )
    }

    fn drmion_doc(members: Vec<Vec<u8>>) -> Vec<u8> {
        let doctype = e_annot(&[sid("doctype")], &e_symbol(sid("doctype")));
        let envelope = e_annot(&[sid("com.amazon.drm.Envelope@1.0")], &e_list(&members));
        let enddoc = e_annot(&[sid("enddoc")], &e_symbol(sid("enddoc")));
        let mut d = bvm();
        d.extend(import_directive());
        d.extend(doctype);
        d.extend(envelope);
        d.extend(enddoc);
        d
    }

    #[test]
    fn decrypt_drmion_plain_and_compressed_pages() {
        let key = [0x33u8; 16];
        let page1 = b"The quick brown fox.".to_vec();
        let page2 = b"jumps over the lazy dog, repeatedly and at length so LZMA helps.".to_vec();

        let metadata = e_annot(
            &[sid("com.amazon.drm.EnvelopeMetadata@1.0")],
            &e_struct(&[e_field(sid("encryption_voucher"), &e_string("voucher"))]),
        );
        let doc = drmion_doc(vec![
            metadata,
            encrypted_page(&key, &page1, false),
            encrypted_page(&key, &page2, true),
        ]);

        let out = decrypt_drmion(&doc, &key).unwrap();
        let mut expected = page1.clone();
        expected.extend_from_slice(&page2);
        assert_eq!(out, expected);
    }

    #[test]
    fn decrypt_drmion_plaintext_member_is_copied() {
        let key = [0x44u8; 16];
        let plain = b"already in the clear".to_vec();
        let member = e_annot(
            &[sid("com.amazon.drm.PlainText@1.0")],
            &e_struct(&[e_field(sid("data"), &e_blob(&plain))]),
        );
        let doc = drmion_doc(vec![member]);
        let out = decrypt_drmion(&doc, &key).unwrap();
        assert_eq!(out, plain);
    }

    // --- Full end-to-end through the KFX-ZIP container ---

    #[test]
    fn decrypt_full_kfx_zip_end_to_end() {
        use std::io::Write;
        use zip::write::SimpleFileOptions;

        let key = [0x9Cu8; 16];
        let p = default_voucher(key);
        let voucher_member = synthesize_voucher(&p);

        let page = b"chapter one, decrypted at last".to_vec();
        let inner = drmion_doc(vec![encrypted_page(&key, &page, false)]);
        // Wrap the DRMION inner stream with the 8-byte magic prefix + 8-byte suffix.
        let mut drmion_member = b"\xeaDRMION\xee".to_vec();
        drmion_member.extend_from_slice(&inner);
        drmion_member.extend_from_slice(&[0u8; 8]);

        // Build a KFX-ZIP.
        let mut zip_bytes = Vec::new();
        {
            let mut w = zip::ZipWriter::new(Cursor::new(&mut zip_bytes));
            let opts =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            w.start_file("book.drmion", opts).unwrap();
            w.write_all(&drmion_member).unwrap();
            w.start_file("voucher.ion", opts).unwrap();
            w.write_all(&voucher_member).unwrap();
            w.start_file("extra.txt", opts).unwrap();
            w.write_all(b"copied verbatim").unwrap();
            w.finish().unwrap();
        }

        let keys = KeyStore {
            pids: vec![
                String::from_utf8(p.dsn.iter().chain(p.secret.iter()).cloned().collect()).unwrap(),
            ],
            ..KeyStore::default()
        };

        let book = decrypt(&zip_bytes, &keys).unwrap();
        assert_eq!(book.extension, "kfx-zip");

        // The rebuilt zip's DRMION member is now the decrypted page bytes.
        let mut archive = zip::ZipArchive::new(Cursor::new(book.data)).unwrap();
        let mut got = std::collections::BTreeMap::new();
        for i in 0..archive.len() {
            use std::io::Read;
            let mut f = archive.by_index(i).unwrap();
            let name = f.name().to_owned();
            let mut b = Vec::new();
            f.read_to_end(&mut b).unwrap();
            got.insert(name, b);
        }
        assert_eq!(got["book.drmion"], page);
        assert_eq!(got["extra.txt"], b"copied verbatim");
    }

    #[test]
    fn non_zip_input_is_not_this_scheme() {
        assert!(matches!(
            decrypt(b"not a zip", &KeyStore::default()),
            Err(SchemeError::NotThisScheme)
        ));
    }
}
