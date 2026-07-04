//! Kobo per-file content decryption (§9.3).
//!
//! Two-layer AES-128-ECB (`user_key` → page key → file contents) followed by
//! CMS/PKCS#7 padding removal, plus the `check()` content sniff used to
//! recognise the correct user key by trial decryption. Reference: `obok.py`
//! `KoboFile.decrypt` / `check` / `__removeaespadding`.

use flamberge_crypto::aes;

use crate::Result;

/// Decrypt one encrypted member: `page_key = AES-ECB(user_key, wrapped)`, then
/// `plain = AES-ECB(page_key, contents)`, with the trailing CMS/PKCS#7 padding
/// stripped (§9.3). Both layers are no-padding ECB, so `contents` must be a
/// whole number of 16-byte blocks (the cipher errors otherwise) and `wrapped`
/// must be exactly one block (else the recovered page key is not a valid AES
/// key and the second layer fails).
pub(super) fn decrypt_member(
    user_key: &[u8; 16],
    wrapped: &[u8],
    contents: &[u8],
) -> Result<Vec<u8>> {
    let page_key = aes::ecb_decrypt(user_key, wrapped)?;
    let plain = aes::ecb_decrypt(&page_key, contents)?;
    Ok(strip_cms_padding(&plain).to_vec())
}

/// Remove trailing CMS/PKCS#7 padding, mirroring obok's `__removeaespadding`
/// (RFC 5652 §6.3): the last byte is the pad length `n`. `n == 1` is stripped
/// unconditionally; `2..=15` only when the byte `n` positions from the end also
/// equals `n`; `16` (a full padding block) or larger — which only occurs on
/// wrong-key garbage — is stripped as-is. Never strips past the start.
fn strip_cms_padding(data: &[u8]) -> &[u8] {
    let Some(&last) = data.last() else {
        return data;
    };
    let n = last as usize;
    if n == 0 || n > data.len() {
        return data;
    }
    // For 1 < n < 16 the reference verifies the padding byte before stripping.
    if (2..16).contains(&n) && data[data.len() - n] as usize != n {
        return data;
    }
    &data[..data.len() - n]
}

/// Outcome of validating a decrypted member against its expected content type.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum CheckResult {
    /// The member has a checkable type and the content is well-formed.
    Passed,
    /// The member has a checkable type and the content is malformed — the
    /// candidate user key is wrong.
    Failed,
    /// The member's type is not one we sniff; nothing was checked.
    Unchecked,
}

/// Validate a decrypted member by sniffing the two content types obok checks
/// (§9.3, `KoboFile.check`): XHTML/XML text and JPEG. The reference reads the
/// media type from the OPF manifest; the file extension is an equivalent proxy
/// for exactly those two checkable types, so no OPF parsing is needed here.
pub(super) fn check(path: &str, contents: &[u8]) -> CheckResult {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".xhtml")
        || lower.ends_with(".html")
        || lower.ends_with(".htm")
        || lower.ends_with(".xml")
    {
        if check_text(contents) {
            CheckResult::Passed
        } else {
            CheckResult::Failed
        }
    } else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") || lower.ends_with(".jpe") {
        if contents.starts_with(&[0xFF, 0xD8, 0xFF]) {
            CheckResult::Passed
        } else {
            CheckResult::Failed
        }
    } else {
        CheckResult::Unchecked
    }
}

/// The XHTML branch of `check`: after skipping any byte-order mark, the first
/// five sampled characters must be printable ASCII (32..=127). The offset and
/// stride mirror obok's handling of UTF-8/UTF-16 BOMs.
fn check_text(contents: &[u8]) -> bool {
    let (offset, stride) = if contents.starts_with(&[0xEF, 0xBB, 0xBF]) {
        (3, 1) // UTF-8 with BOM
    } else if contents.starts_with(&[0xFE, 0xFF]) {
        (3, 2) // UTF-16BE (matches obok's textoffset=3, stride=2)
    } else if contents.starts_with(&[0xFF, 0xFE]) {
        (2, 2) // UTF-16LE
    } else {
        (0, 1) // assume UTF-8 without BOM
    };
    (0..5).all(|i| matches!(contents.get(offset + i * stride), Some(&b) if (32..=127).contains(&b)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_full_padding_block() {
        let mut data = vec![b'A'; 16];
        data.extend([16u8; 16]);
        assert_eq!(strip_cms_padding(&data), &[b'A'; 16]);
    }

    #[test]
    fn strips_partial_and_single_byte_padding() {
        assert_eq!(strip_cms_padding(b"hello\x03\x03\x03"), b"hello");
        assert_eq!(strip_cms_padding(b"hello\x01"), b"hello");
    }

    #[test]
    fn leaves_inconsistent_padding_untouched() {
        // Last byte says 3, but the byte 3 from the end is not 3 → not stripped.
        assert_eq!(strip_cms_padding(b"helloX\x03"), b"helloX\x03");
    }

    #[test]
    fn text_check_accepts_ascii_and_boms() {
        assert_eq!(check("a.xhtml", b"<?xml version"), CheckResult::Passed);
        assert_eq!(check("a.xhtml", b"\xef\xbb\xbf<html"), CheckResult::Passed);
    }

    #[test]
    fn text_check_rejects_binary() {
        assert_eq!(
            check("a.xhtml", b"\x00\x01\x02\x03\x04\x05"),
            CheckResult::Failed
        );
    }

    #[test]
    fn jpeg_check_and_unchecked_types() {
        assert_eq!(check("i.jpg", b"\xff\xd8\xff\xe0"), CheckResult::Passed);
        assert_eq!(check("i.jpg", b"not a jpeg"), CheckResult::Failed);
        assert_eq!(check("f.otf", b"anything"), CheckResult::Unchecked);
    }

    #[test]
    fn two_layer_round_trip() {
        let user_key = [0x2bu8; 16];
        let page_key = [0x77u8; 16];
        let wrapped = aes::ecb_encrypt(&user_key, &page_key).unwrap();

        let text = b"<?xml version=\"1.0\"?><html>hi</html>";
        let mut padded = text.to_vec();
        let pad = 16 - (padded.len() % 16);
        padded.extend(std::iter::repeat_n(pad as u8, pad));
        let ciphertext = aes::ecb_encrypt(&page_key, &padded).unwrap();

        let plain = decrypt_member(&user_key, &wrapped, &ciphertext).unwrap();
        assert_eq!(plain, text);
        assert_eq!(check("c.xhtml", &plain), CheckResult::Passed);
    }
}
