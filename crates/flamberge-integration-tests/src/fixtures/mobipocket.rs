//! Mobipocket / Kindle type-2 (PID) fixture (§2).
//!
//! Builds a minimal but structurally faithful 2-section `BOOKMOBI` PalmDB:
//! record 0 (PalmDoc + MOBI header + an EXTH title + a 48-byte DRM voucher) and
//! record 1 (the PC1-encrypted text). Decryption chain (§2.3): `temp_key =
//! PC1(KEYVEC1, pid.padded16)`; the voucher cookie is `PC1(temp_key, ver ||
//! flags=1 || finalkey || 0 || 0)`; text records are `PC1(finalkey, plaintext)`.
//!
//! Mirrors `mobipocket.rs` / `flamberge-cli/tests/mobipocket_cli.rs`, rebuilt on
//! public APIs. No real book is embedded (see [`crate::fixtures`]).

use flamberge_crypto::pc1;
use flamberge_schemes::mobipocket::KEYVEC1;
use flamberge_schemes::KeyStore;

const VOUCHER_LEN: usize = 0x30;
const PID: &str = "12345678";
const PLAINTEXT: &[u8] = b"Hello, Mobipocket world!";
const TITLE: &str = "Hello Title";

/// A synthesized Mobipocket book plus the keys to decrypt it.
pub struct MobiFixture {
    /// The `.azw`/`.mobi` PalmDB image, for `flamberge_schemes::decrypt(_, "azw", _)`.
    pub image: Vec<u8>,
    /// A `KeyStore` carrying the correct PID.
    pub keys: KeyStore,
    /// A `KeyStore` with a wrong PID, for the negative test.
    pub wrong_keys: KeyStore,
    /// Byte range of the decrypted text record within the output image.
    pub rec1_range: std::ops::Range<usize>,
    /// Expected recovered plaintext of the text record.
    pub plaintext: &'static [u8],
    /// Expected recovered book title (from the EXTH 503 record).
    pub title: &'static str,
}

/// Build the 48-byte DRM voucher for `finalkey` under `temp_key` (§2.3).
fn make_voucher(temp_key: &[u8], ver: u32, finalkey: &[u8; 16]) -> Vec<u8> {
    let mut cookie_plain = Vec::new();
    cookie_plain.extend_from_slice(&ver.to_be_bytes());
    cookie_plain.extend_from_slice(&1u32.to_be_bytes()); // flags & 0x1F == 1
    cookie_plain.extend_from_slice(finalkey);
    cookie_plain.extend_from_slice(&0u32.to_be_bytes()); // expiry
    cookie_plain.extend_from_slice(&0u32.to_be_bytes()); // expiry2
    let cookie_enc = pc1::encrypt(temp_key, &cookie_plain).unwrap();
    let cksum = (temp_key.iter().map(|&b| b as u32).sum::<u32>() & 0xFF) as u8;

    let mut v = Vec::with_capacity(VOUCHER_LEN);
    v.extend_from_slice(&ver.to_be_bytes()); // verification (== ver)
    v.extend_from_slice(&0u32.to_be_bytes()); // size
    v.extend_from_slice(&0u32.to_be_bytes()); // type
    v.push(cksum);
    v.extend_from_slice(&[0, 0, 0]); // pad
    v.extend_from_slice(&cookie_enc); // cookie(32)
    assert_eq!(v.len(), VOUCHER_LEN);
    v
}

/// A single-record EXTH block carrying the book title (record type 503).
fn exth_with_title(title: &str) -> Vec<u8> {
    let content = title.as_bytes();
    let rec_size = 8 + content.len();
    let mut records = Vec::new();
    records.extend_from_slice(&503u32.to_be_bytes());
    records.extend_from_slice(&(rec_size as u32).to_be_bytes());
    records.extend_from_slice(content);

    let mut exth = Vec::new();
    exth.extend_from_slice(b"EXTH");
    exth.extend_from_slice(&((12 + records.len()) as u32).to_be_bytes());
    exth.extend_from_slice(&1u32.to_be_bytes()); // nitems
    exth.extend_from_slice(&records);
    exth
}

/// Build the type-2 (PID) Mobipocket fixture.
pub fn fixture() -> MobiFixture {
    let mut bigpid = PID.as_bytes().to_vec();
    bigpid.resize(16, 0);
    let temp_key = pc1::encrypt(&KEYVEC1, &bigpid).unwrap();
    let finalkey = *b"0123456789abcdef";
    let voucher = make_voucher(&temp_key, 0xCAFE, &finalkey);

    // Record 0 = 16-byte PalmDoc header + 0xE4 MOBI header + EXTH + voucher.
    let mobi_length: u32 = 0xE4;
    let mut rec0 = vec![0u8; 16 + mobi_length as usize];
    rec0[0x00..0x02].copy_from_slice(&1u16.to_be_bytes()); // compression: none
    rec0[0x08..0x0A].copy_from_slice(&1u16.to_be_bytes()); // one text record
    rec0[0x0C..0x0E].copy_from_slice(&2u16.to_be_bytes()); // encryption type 2
    rec0[0x10..0x14].copy_from_slice(b"MOBI");
    rec0[0x14..0x18].copy_from_slice(&mobi_length.to_be_bytes());
    rec0[0x1C..0x20].copy_from_slice(&65001u32.to_be_bytes()); // codepage utf-8
    rec0[0x68..0x6C].copy_from_slice(&6u32.to_be_bytes()); // mobi_version < 8 → .mobi
    rec0[0x80..0x84].copy_from_slice(&0x40u32.to_be_bytes()); // EXTH present
    rec0[0xF2..0xF4].copy_from_slice(&0u16.to_be_bytes()); // extra_data_flags 0
    rec0.extend_from_slice(&exth_with_title(TITLE));
    let drm_ptr = rec0.len() as u32;
    rec0.extend_from_slice(&voucher);
    rec0[0xA8..0xAC].copy_from_slice(&drm_ptr.to_be_bytes());
    rec0[0xAC..0xB0].copy_from_slice(&1u32.to_be_bytes()); // voucher count
    rec0[0xB0..0xB4].copy_from_slice(&(VOUCHER_LEN as u32).to_be_bytes());

    let rec1 = pc1::encrypt(&finalkey, PLAINTEXT).unwrap();

    // Assemble the PalmDB: 78-byte header + 2×8 record table + the two records.
    const HEADER: usize = 78;
    let table = 2 * 8;
    let rec0_off = HEADER + table;
    let rec1_off = rec0_off + rec0.len();
    let mut image = vec![0u8; rec1_off + rec1.len()];
    image[0x3C..0x44].copy_from_slice(b"BOOKMOBI");
    image[0x4C..0x4E].copy_from_slice(&2u16.to_be_bytes());
    image[HEADER..HEADER + 4].copy_from_slice(&(rec0_off as u32).to_be_bytes());
    image[HEADER + 8..HEADER + 12].copy_from_slice(&(rec1_off as u32).to_be_bytes());
    image[rec0_off..rec1_off].copy_from_slice(&rec0);
    image[rec1_off..].copy_from_slice(&rec1);

    MobiFixture {
        image,
        keys: KeyStore {
            pids: vec![PID.to_string()],
            ..KeyStore::default()
        },
        wrong_keys: KeyStore {
            pids: vec!["00000000".to_string()],
            ..KeyStore::default()
        },
        rec1_range: rec1_off..rec1_off + rec1.len(),
        plaintext: PLAINTEXT,
        title: TITLE,
    }
}
