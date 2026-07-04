//! Cross-scheme end-to-end suite: every implemented scheme decrypts a synthesized
//! book through the top-level `flamberge_schemes::decrypt` dispatch (exercising
//! extension routing + key handling), and a wrong key fails cleanly.
//!
//! Fixtures are synthesized in `flamberge_integration_tests::fixtures`; none
//! embeds real DRM-protected content. See that module for provenance.

use flamberge_integration_tests::fixtures;
use flamberge_schemes::{decrypt, SchemeError};

// --- Mobipocket / Kindle PID (§2) ----------------------------------------

#[test]
fn mobipocket_round_trip() {
    let f = fixtures::mobipocket::fixture();
    let book = decrypt(&f.image, "azw", &f.keys).expect("Mobipocket should decrypt");
    assert_eq!(book.extension, "mobi");
    assert_eq!(book.title.as_deref(), Some(f.title));
    assert_eq!(&book.data[f.rec1_range], f.plaintext);
}

#[test]
fn mobipocket_wrong_pid_fails_cleanly() {
    let f = fixtures::mobipocket::fixture();
    assert!(matches!(
        decrypt(&f.image, "azw", &f.wrong_keys),
        Err(SchemeError::NoKeyWorked)
    ));
}

// --- Kobo KEPUB (§9) -----------------------------------------------------

#[test]
fn kobo_round_trip() {
    let f = fixtures::kobo::fixture();
    let book = decrypt(&f.kepub, "kepub", &f.keys).expect("Kobo should decrypt");
    assert_eq!(book.extension, "epub");
    assert_eq!(book.title.as_deref(), Some(f.title));
    let out = fixtures::read_zip(&book.data);
    assert_eq!(out[f.xhtml_path], f.expected_xhtml);
    // The DRM-free member is preserved verbatim.
    assert_eq!(out[f.plain_path], f.expected_plain);
}

#[test]
fn kobo_no_user_key_fails_cleanly() {
    let f = fixtures::kobo::fixture();
    assert!(matches!(
        decrypt(&f.kepub, "kepub", &f.wrong_keys),
        Err(SchemeError::NoKeyWorked)
    ));
}

// --- KFX-ZIP (§3) --------------------------------------------------------

#[test]
fn kfx_round_trip() {
    let f = fixtures::kfx::fixture();
    let book = decrypt(&f.zip, "kfx-zip", &f.keys).expect("KFX should decrypt");
    assert_eq!(book.extension, "kfx-zip");
    let out = fixtures::read_zip(&book.data);
    // The DRMION member is now the decrypted page; the plaintext member survives.
    assert_eq!(out[f.drmion_name], f.expected_page);
    assert_eq!(out[f.extra_name], f.expected_extra);
}

#[test]
fn kfx_wrong_pid_fails_cleanly() {
    let f = fixtures::kfx::fixture();
    assert!(matches!(
        decrypt(&f.zip, "kfx-zip", &f.wrong_keys),
        Err(SchemeError::NoKeyWorked)
    ));
}

// --- eReader .pdb (§8) ---------------------------------------------------

#[test]
fn ereader_round_trip() {
    let f = fixtures::ereader::fixture();
    let book = decrypt(&f.pdb, "pdb", &f.keys).expect("eReader should decrypt");
    assert_eq!(book.extension, "pmlz");
    assert_eq!(book.title.as_deref(), Some(f.title));
    let out = fixtures::read_zip(&book.data);
    assert_eq!(out[f.pml_name], f.expected_pml);
    assert_eq!(out[f.image_name], f.expected_image);
}

#[test]
fn ereader_wrong_key_fails_cleanly() {
    let f = fixtures::ereader::fixture();
    assert!(matches!(
        decrypt(&f.pdb, "pdb", &f.wrong_keys),
        Err(SchemeError::NoKeyWorked)
    ));
}

// --- Topaz TPZ0 (§5) -----------------------------------------------------

#[test]
fn topaz_round_trip() {
    let f = fixtures::topaz::fixture();
    let book = decrypt(&f.file, "tpz", &f.keys).expect("Topaz should decrypt");
    assert_eq!(book.extension, "tpz");
    assert_eq!(book.title.as_deref(), Some(f.title));

    let out = flamberge_formats::topaz_container::TopazContainer::parse(&book.data).unwrap();
    // The dkey record is dropped from the decrypted container.
    assert!(!out.header_records.contains_key(b"dkey".as_slice()));
    let r0 = out.payload_record(&book.data, b"page0", 0).unwrap();
    assert!(!r0.encrypted && !r0.compressed);
    assert_eq!(r0.raw, f.plain0);
    // The compressed+encrypted page comes back inflated in the clear.
    let r1 = out.payload_record(&book.data, b"page1", 0).unwrap();
    assert!(!r1.encrypted && !r1.compressed);
    assert_eq!(r1.raw, f.plain1);
}

#[test]
fn topaz_wrong_pid_fails_cleanly() {
    let f = fixtures::topaz::fixture();
    assert!(matches!(
        decrypt(&f.file, "tpz", &f.wrong_keys),
        Err(SchemeError::NoKeyWorked)
    ));
}

// --- EBX_HANDLER PDF: ADEPT (§7.4) and B&N (§4.4) ------------------------

#[test]
fn adept_pdf_round_trip() {
    let f = fixtures::pdf::adept();
    let book = decrypt(&f.pdf, "pdf", &f.keys).expect("ADEPT PDF should decrypt");
    assert_eq!(book.extension, "pdf");
    assert_eq!(fixtures::pdf::read_back(&book.data), (f.page, f.secret));
}

#[test]
fn adept_pdf_wrong_key_fails_cleanly() {
    let f = fixtures::pdf::adept();
    assert!(matches!(
        decrypt(&f.pdf, "pdf", &f.wrong_keys),
        Err(SchemeError::NoKeyWorked)
    ));
}

#[test]
fn ignoble_pdf_round_trip() {
    let f = fixtures::pdf::ignoble();
    let book = decrypt(&f.pdf, "pdf", &f.keys).expect("B&N PDF should decrypt");
    assert_eq!(book.extension, "pdf");
    assert_eq!(fixtures::pdf::read_back(&book.data), (f.page, f.secret));
}

#[test]
fn ignoble_pdf_wrong_key_fails_cleanly() {
    let f = fixtures::pdf::ignoble();
    assert!(matches!(
        decrypt(&f.pdf, "pdf", &f.wrong_keys),
        Err(SchemeError::NoKeyWorked)
    ));
}

// --- EPUB: Adobe ADEPT (§7.3) and Barnes & Noble (§4.4) ------------------

#[test]
fn adept_epub_round_trip() {
    let f = fixtures::epub::adept();
    let book = decrypt(&f.epub, "epub", &f.keys).expect("ADEPT EPUB should decrypt");
    assert_eq!(book.extension, "epub");
    let out = fixtures::read_zip(&book.data);
    for (path, plaintext) in &f.decrypted_members {
        assert_eq!(&out[*path], plaintext, "recovered {path}");
    }
    // The unencrypted member survives; the DRM META files are dropped.
    assert_eq!(out["OEBPS/content.opf"], b"<package/>");
    assert!(!out.contains_key(flamberge_formats::ocf::RIGHTS_XML));
    assert!(!out.contains_key(flamberge_formats::ocf::ENCRYPTION_XML));
}

#[test]
fn adept_epub_wrong_key_fails_cleanly() {
    let f = fixtures::epub::adept();
    // A wrong user key must not yield a book (so the CLI writes no output file).
    assert!(matches!(
        decrypt(&f.epub, "epub", &f.wrong_keys),
        Err(SchemeError::NoKeyWorked)
    ));
}

#[test]
fn ignoble_epub_round_trip() {
    let f = fixtures::epub::ignoble();
    let book = decrypt(&f.epub, "epub", &f.keys).expect("B&N EPUB should decrypt");
    assert_eq!(book.extension, "epub");
    let out = fixtures::read_zip(&book.data);
    for (path, plaintext) in &f.decrypted_members {
        assert_eq!(&out[*path], plaintext, "recovered {path}");
    }
    assert_eq!(out["OEBPS/content.opf"], b"<package/>");
    assert!(!out.contains_key(flamberge_formats::ocf::RIGHTS_XML));
}

#[test]
fn ignoble_epub_wrong_key_fails_cleanly() {
    let f = fixtures::epub::ignoble();
    assert!(matches!(
        decrypt(&f.epub, "epub", &f.wrong_keys),
        Err(SchemeError::NoKeyWorked)
    ));
}
