//! KFX-ZIP fixture (§3): voucher unwrap + content-page decryption.
//!
//! Builds a KFX-ZIP holding a `book.drmion` member (magic `\xeaDRMION\xee` +
//! inner ION `Envelope` with an AES-128-CBC-encrypted page + 8-byte suffix), a
//! `voucher.ion` `VoucherEnvelope`, and a plaintext member. The voucher's KeySet
//! (carrying the content key) is AES-256-CBC-encrypted under a KEK derived from
//! the PID (`dsn || secret`): `KEK = HMAC-SHA256(obfuscate(sharedSecret,
//! version), "PIDv3")`. The decryptor recovers the content key from the voucher,
//! then decrypts the page.
//!
//! This uses a **version-1** `VoucherEnvelope`, whose obfuscation is the identity
//! (§3.3) — so the KEK derivation is reproducible here without the version-2+
//! obfuscation table (which is scheme-private; the v2+ vectors are exercised by
//! `kfx.rs`'s own unit tests). A hand-rolled binary-ION encoder mirrors the one in
//! that scheme's tests. No real book is embedded (see [`crate::fixtures`]).

use std::io::{Cursor, Write};

use flamberge_crypto::{aes, kdf};
use flamberge_formats::ion::protected_data_symbols;
use flamberge_schemes::KeyStore;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

use super::pkcs7_pad;

// A 16-byte dsn + 40-byte secret → a 56-char PID, split as (16, 40).
const DSN: &[u8] = b"0123456789abcdef";
const SECRET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCD";
const VERSION: i64 = 1; // identity obfuscation

/// A synthesized KFX book plus the keys to decrypt it.
pub struct KfxFixture {
    /// The KFX-ZIP archive, for `flamberge_schemes::decrypt(_, "kfx-zip", _)`.
    pub zip: Vec<u8>,
    /// A `KeyStore` carrying the correct PID (`dsn || secret`).
    pub keys: KeyStore,
    /// A `KeyStore` with a wrong PID, for the negative test.
    pub wrong_keys: KeyStore,
    /// The DRMION member's name.
    pub drmion_name: &'static str,
    /// Expected recovered page plaintext.
    pub expected_page: Vec<u8>,
    /// A plaintext member's name (copied verbatim).
    pub extra_name: &'static str,
    /// Expected bytes of the plaintext member.
    pub expected_extra: &'static [u8],
}

// --- Minimal binary-ION encoder (mirrors `kfx.rs` / `ion.rs` test helpers) ---

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
fn e_symbol(sid_val: u64) -> Vec<u8> {
    let mut m = Vec::new();
    let mut n = sid_val;
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
fn e_field(sid_val: u64, val: &[u8]) -> Vec<u8> {
    let mut out = varuint(sid_val);
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

// --- Voucher + page synthesis ---

/// Build a version-1 `VoucherEnvelope` ION stream that unwraps to `content_key`.
fn synthesize_voucher(content_key: &[u8; 16]) -> Vec<u8> {
    // 1. KeySet plaintext ION carrying the content key.
    let keyset = ion_doc(e_annot(
        &[sid("com.amazon.drm.KeySet@1.0")],
        &e_list(&[e_annot(
            &[sid("com.amazon.drm.SecretKey@1.0")],
            &e_struct(&[
                e_field(sid("algorithm"), &e_string("AES")),
                e_field(sid("format"), &e_string("RAW")),
                e_field(sid("encoded"), &e_blob(content_key)),
            ]),
        )]),
    ));

    // 2. Derive the same KEK the decryptor will. Lock parameters are sorted; for
    //    version 1 the shared secret is used as-is (identity obfuscation).
    let enc_algorithm = "AES";
    let enc_transformation = "AES/CBC/PKCS5Padding";
    let hash_algorithm = "SHA-256";
    let mut params = vec!["ACCOUNT_SECRET", "CLIENT_ID"];
    params.sort_unstable();

    let mut shared =
        format!("PIDv3{enc_algorithm}{enc_transformation}{hash_algorithm}").into_bytes();
    for param in &params {
        match *param {
            "ACCOUNT_SECRET" => {
                shared.extend_from_slice(b"ACCOUNT_SECRET");
                shared.extend_from_slice(SECRET);
            }
            "CLIENT_ID" => {
                shared.extend_from_slice(b"CLIENT_ID");
                shared.extend_from_slice(DSN);
            }
            _ => unreachable!(),
        }
    }
    let kek = kdf::hmac_sha256(&shared, b"PIDv3"); // version 1: shared_secret == shared
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
                    &e_struct(&[e_field(sid("license_type"), &e_string("Purchase"))]),
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
                e_field(sid("encryption_algorithm"), &e_string(enc_algorithm)),
                e_field(
                    sid("encryption_transformation"),
                    &e_string(enc_transformation),
                ),
                e_field(sid("hashing_algorithm"), &e_string(hash_algorithm)),
                e_field(sid("lock_parameters"), &e_list(&lock_items)),
            ]),
        ),
    );
    let voucher_field = e_field(sid("voucher"), &e_blob(&inner));

    ion_doc(e_annot(
        &[sid(&format!("com.amazon.drm.VoucherEnvelope@{VERSION}.0"))],
        &e_struct(&[strategy, voucher_field]),
    ))
}

/// An AES-128-CBC-encrypted `EncryptedPage` (uncompressed).
fn encrypted_page(content_key: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let iv = [0x22u8; 16];
    let ct = aes::cbc_encrypt(content_key, &iv, &pkcs7_pad(plaintext, 16)).unwrap();
    e_annot(
        &[sid("com.amazon.drm.EncryptedPage@1.0")],
        &e_struct(&[
            e_field(sid("cipher_text"), &e_blob(&ct)),
            e_field(sid("cipher_iv"), &e_blob(&iv)),
        ]),
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

/// Build the KFX-ZIP fixture.
pub fn fixture() -> KfxFixture {
    let content_key = [0x9Cu8; 16];
    let voucher_member = synthesize_voucher(&content_key);

    let page = b"chapter one, decrypted at last".to_vec();
    let inner = drmion_doc(vec![encrypted_page(&content_key, &page)]);
    // Wrap the DRMION inner stream: 8-byte magic prefix + 8-byte suffix.
    let mut drmion_member = b"\xeaDRMION\xee".to_vec();
    drmion_member.extend_from_slice(&inner);
    drmion_member.extend_from_slice(&[0u8; 8]);

    let mut zip = Vec::new();
    {
        let mut w = ZipWriter::new(Cursor::new(&mut zip));
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        w.start_file("book.drmion", opts).unwrap();
        w.write_all(&drmion_member).unwrap();
        w.start_file("voucher.ion", opts).unwrap();
        w.write_all(&voucher_member).unwrap();
        w.start_file("extra.txt", opts).unwrap();
        w.write_all(b"copied verbatim").unwrap();
        w.finish().unwrap();
    }

    let pid: String = DSN
        .iter()
        .chain(SECRET.iter())
        .map(|&b| b as char)
        .collect();
    // A wrong PID of the same (16, 40) split — decryption fails, no key matches.
    let wrong_pid = "f".repeat(56);

    KfxFixture {
        zip,
        keys: KeyStore {
            pids: vec![pid],
            ..KeyStore::default()
        },
        wrong_keys: KeyStore {
            pids: vec![wrong_pid],
            ..KeyStore::default()
        },
        drmion_name: "book.drmion",
        expected_page: page,
        extra_name: "extra.txt",
        expected_extra: b"copied verbatim",
    }
}
