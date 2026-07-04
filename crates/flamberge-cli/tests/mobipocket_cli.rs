//! End-to-end integration test for the `flamberge` binary against Mobipocket DRM.
//!
//! ## Fixture provenance
//!
//! No redistributable DRM-protected Mobipocket file exists (shipping one would
//! distribute copyrighted, DRMed content), so this test **synthesizes** a
//! minimal but structurally faithful type-2 (`PID`) Mobipocket image at run
//! time, exactly as the real format is laid out (see `docs/DEDRM_SCHEMES.md`
//! §2). Construction:
//!
//! 1. Pick a known PID (`12345678`) and book key (`finalkey`).
//! 2. `temp_key = PC1_encrypt(KEYVEC1, pid.padded_to_16)` — the per-PID key.
//! 3. Wrap `finalkey` in a 48-byte DRM voucher whose cookie is
//!    `PC1_encrypt(temp_key, ver || flags=1 || finalkey || 0 || 0)` and whose
//!    checksum byte is `sum(temp_key) & 0xFF`.
//! 4. PC1-encrypt the known plaintext under `finalkey` to make text record 1.
//! 5. Assemble a 2-section `BOOKMOBI` PalmDB: record 0 (PalmDoc + MOBI header +
//!    EXTH with a 503 title + the voucher) and record 1 (the ciphertext).
//!
//! Decrypting with the correct PID must recover the plaintext; the byte layout
//! mirrors what `flamberge-schemes::mobipocket` already round-trips in its unit
//! tests, but here it is exercised through the actual compiled CLI, covering
//! argument parsing, key handling, output naming, and process exit codes.

use std::path::PathBuf;
use std::process::Command;

use flamberge_crypto::pc1;
use flamberge_schemes::mobipocket::KEYVEC1;

const VOUCHER_LEN: usize = 0x30;
const PID: &str = "12345678";
const PLAINTEXT: &[u8] = b"Hello, Mobipocket world!";
const TITLE: &str = "Hello Title";

/// Build the 48-byte DRM voucher for `finalkey` under `temp_key` (`§2.3`).
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

/// Build the whole synthetic `.azw` file image and the byte range of record 1.
fn synth_book() -> (Vec<u8>, std::ops::Range<usize>) {
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

    (image, rec1_off..rec1_off + rec1.len())
}

/// Create a fresh, uniquely named temp directory for one test.
fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("flamberge-it-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn flamberge() -> Command {
    Command::new(env!("CARGO_BIN_EXE_flamberge"))
}

#[test]
fn decrypts_with_correct_pid_and_names_by_title() {
    let dir = temp_dir("ok");
    // Opaque Amazon-style ASIN stem (B + 9 alnum) → title-based output naming.
    let input = dir.join("B00TESTPI0.azw");
    let (image, rec1_range) = synth_book();
    std::fs::write(&input, &image).unwrap();

    let status = flamberge()
        .arg("decrypt")
        .arg(&input)
        .arg("--pid")
        .arg(PID)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "decrypt should succeed with the right PID"
    );

    // AC#1/#2: DRM-free file with the correct extension and title-based name.
    let expected = dir.join("B00TESTPI0_Hello Title_nodrm.mobi");
    assert!(
        expected.exists(),
        "expected output {expected:?} was not written"
    );

    // AC#3: the decrypted text record equals the known plaintext.
    let out = std::fs::read(&expected).unwrap();
    assert_eq!(&out[rec1_range], PLAINTEXT);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn batch_decrypts_directory_and_skips_strays() {
    let dir = temp_dir("batch");
    // A real (synthetic) DRMed book plus a stray non-ebook file in one folder.
    let (image, _) = synth_book();
    std::fs::write(dir.join("B00TESTPI0.azw"), &image).unwrap();
    std::fs::write(dir.join("notes.txt"), b"not an ebook").unwrap();

    let output = flamberge()
        .arg("decrypt")
        .arg(&dir) // directory input → batch mode
        .arg("--pid")
        .arg(PID)
        .output()
        .unwrap();

    // The stray file is skipped (not a failure), so the run succeeds overall.
    assert!(
        output.status.success(),
        "batch run should succeed when the only non-ok file is skipped; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("OK "), "expected an OK line, got: {stdout}");
    assert!(
        stdout.contains("SKIP") && stdout.contains("notes.txt"),
        "stray file should be reported as skipped, got: {stdout}"
    );
    assert!(
        stdout.contains("1 ok, 0 failed, 1 skipped"),
        "expected batch tally, got: {stdout}"
    );
    // The decrypted book was written; the stray file produced no output.
    assert!(dir.join("B00TESTPI0_Hello Title_nodrm.mobi").exists());
    assert!(!dir.join("notes_nodrm.txt").exists());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wrong_pid_fails_cleanly_without_writing_output() {
    let dir = temp_dir("badpid");
    let input = dir.join("B00TESTPI0.azw");
    let (image, _) = synth_book();
    std::fs::write(&input, &image).unwrap();

    let output = flamberge()
        .arg("decrypt")
        .arg(&input)
        .arg("--pid")
        .arg("00000000") // wrong PID
        .output()
        .unwrap();

    // AC#4: non-zero exit, clear "no key" message, and no partial output file.
    assert!(!output.status.success(), "wrong PID must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no candidate key"),
        "stderr should explain that no key worked, got: {stderr}"
    );
    let would_be = dir.join("B00TESTPI0_Hello Title_nodrm.mobi");
    assert!(
        !would_be.exists(),
        "no output file should be written on failure"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
