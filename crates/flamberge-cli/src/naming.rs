//! Output-file naming, ported from `k4mobidedrm.py::decryptBook`/`cleanup_name`.

use std::path::{Path, PathBuf};

/// Build the default output path, mirroring `k4mobidedrm.py::decryptBook`.
///
/// When the source stem is an opaque Amazon download name (ASIN or UUID) and a
/// title is known, the cleaned title is appended so the file is recognizable:
/// `<stem>_<clean title>_nodrm.<ext>`. Otherwise the stem already reads well
/// (E-Ink Kindle names, side-loaded books) and is used as-is:
/// `<stem>_nodrm.<ext>`. Over-long names are shortened as the plugin does.
///
/// `dir` is the destination directory; the input's own parent is used when the
/// caller passes `None`.
pub fn default_output(input: &Path, ext: &str, title: Option<&str>, dir: Option<&Path>) -> PathBuf {
    let stem = input.file_stem().and_then(|s| s.to_str()).unwrap_or("book");
    let parent = dir
        .or_else(|| input.parent())
        .unwrap_or_else(|| Path::new("."));

    let mut name = match title {
        Some(t) if is_amazon_download_name(stem) => format!("{stem}_{}", cleanup_name(t)),
        _ => stem.to_string(),
    };
    // Avoid excessively long names (plugin: >150 chars → first 99 + "--" + last 49).
    let chars: Vec<char> = name.chars().collect();
    if chars.len() > 150 {
        let head: String = chars[..99].iter().collect();
        let tail: String = chars[chars.len() - 49..].iter().collect();
        name = format!("{head}--{tail}");
    }
    parent.join(format!("{name}_nodrm.{ext}"))
}

/// True if `stem` is an opaque Amazon download name: an ASIN
/// (`B` + 9 uppercase-alnum, optional `_EBOK`/`_EBSP`/`_sample`) or a 36-char
/// UUID (hex digits and hyphens). Mirrors the two `re.match` checks in
/// `decryptBook`. (The plugin's UUID regex is malformed and never matches; we
/// implement its evident intent.)
fn is_amazon_download_name(stem: &str) -> bool {
    is_asin(stem) || is_uuid(stem)
}

fn is_asin(stem: &str) -> bool {
    let core = stem
        .strip_suffix("_EBOK")
        .or_else(|| stem.strip_suffix("_EBSP"))
        .or_else(|| stem.strip_suffix("_sample"))
        .unwrap_or(stem);
    let bytes = core.as_bytes();
    bytes.len() == 10
        && bytes[0] == b'B'
        && bytes[1..]
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

fn is_uuid(stem: &str) -> bool {
    stem.len() == 36 && stem.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
}

/// Sanitize a book title into a filesystem-friendly name, porting
/// `k4mobidedrm.py::cleanup_name` byte-for-byte (including the unicode dash
/// substitutions, which are then dropped by the `<= 126` filter — matching the
/// plugin's exact output). An empty result becomes `DecryptedBook`.
fn cleanup_name(name: &str) -> String {
    let mut s = name
        .replace('<', "[")
        .replace('>', "]")
        .replace(" : ", " \u{2013} ")
        .replace(": ", " \u{2013} ")
        .replace(':', "\u{2014}")
        .replace(['/', '\\', '|'], "_")
        .replace('"', "'")
        .replace('*', "_")
        .replace('?', "");
    // Collapse all whitespace to single spaces, then trim.
    s = s
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect();
    // Drop control (< 32) and non-ASCII (> 126) characters.
    let mut s: String = s
        .trim()
        .chars()
        .filter(|&c| (c as u32) >= 32 && (c as u32) <= 126)
        .collect();
    // Remove leading and trailing dots.
    let start = s.find(|c| c != '.').unwrap_or(s.len());
    s.drain(..start);
    while s.ends_with('.') {
        s.pop();
    }
    if s.is_empty() {
        s = "DecryptedBook".to_string();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asin_names_are_recognized() {
        assert!(is_amazon_download_name("B00ABCDEF0"));
        assert!(is_amazon_download_name("B0011AB2CD_EBOK"));
        assert!(is_amazon_download_name("B0011AB2CD_EBSP"));
        assert!(is_amazon_download_name("B0011AB2CD_sample"));
        // 36-char UUID-style download name.
        assert!(is_amazon_download_name(
            "0123456789ABCDEF0123456789ABCDEF-012"
        ));
        // Ordinary, human-readable stems are left alone.
        assert!(!is_amazon_download_name("My Great Book"));
        assert!(!is_amazon_download_name("B00ABCDEF")); // too short
        assert!(!is_amazon_download_name("b00abcdef0")); // lowercase 'b'
        assert!(!is_amazon_download_name("B00abcdef0")); // lowercase body
    }

    #[test]
    fn cleanup_name_substitutes_and_strips() {
        assert_eq!(cleanup_name("Book/Title|X"), "Book_Title_X");
        assert_eq!(cleanup_name("A <tag> here"), "A [tag] here");
        assert_eq!(cleanup_name("What? Really*"), "What Really_");
        // Colon becomes an em-dash which is then dropped (> 126); ": " path too.
        assert_eq!(cleanup_name("Title: Subtitle"), "Title  Subtitle");
        // Non-ASCII is removed entirely.
        assert_eq!(cleanup_name("Café"), "Caf");
        // Leading/trailing dots trimmed; empty falls back.
        assert_eq!(cleanup_name("...hidden..."), "hidden");
        assert_eq!(cleanup_name("   "), "DecryptedBook");
        assert_eq!(cleanup_name("\u{2014}"), "DecryptedBook");
    }

    #[test]
    fn default_output_appends_title_for_asin() {
        let out = default_output(
            Path::new("/books/B00ABCDEF0.azw"),
            "mobi",
            Some("My Title"),
            None,
        );
        assert_eq!(out, Path::new("/books/B00ABCDEF0_My Title_nodrm.mobi"));
    }

    #[test]
    fn default_output_keeps_plain_stem() {
        // A readable stem is untouched even when a title is available.
        let out = default_output(
            Path::new("/books/Great Read.azw3"),
            "azw3",
            Some("Ignored"),
            None,
        );
        assert_eq!(out, Path::new("/books/Great Read_nodrm.azw3"));
        // No title → stem as-is.
        let out = default_output(Path::new("book.mobi"), "mobi", None, None);
        assert_eq!(out, Path::new("book_nodrm.mobi"));
    }

    #[test]
    fn default_output_honors_dir_override() {
        let out = default_output(
            Path::new("/books/Great Read.azw3"),
            "epub",
            None,
            Some(Path::new("/out")),
        );
        assert_eq!(out, Path::new("/out/Great Read_nodrm.epub"));
    }

    #[test]
    fn default_output_shortens_long_names() {
        let long_title = "x".repeat(300);
        let out = default_output(Path::new("B00ABCDEF0.azw"), "mobi", Some(&long_title), None);
        let name = out.file_name().unwrap().to_str().unwrap();
        // Shortened to first 99 + "--" + last 49 chars, then "_nodrm.mobi".
        assert!(name.contains("--"));
        assert!(name.ends_with("_nodrm.mobi"));
        assert!(name.len() < 170);
    }
}
