//! macOS ADEPT key extraction: locate and read `activation.dat` (fully offline).
//!
//! `activation.dat` stores the RSA private key base64-encoded behind a fixed
//! 26-byte header and is **not** encrypted (unlike the Windows registry blob).
//! This module owns only the host-specific *locate + read*; the parse/decode is
//! the platform-independent [`super::parse_activation_dat`].
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §7.2 (`adobekey.py`, `isosx` branch).

use std::path::{Path, PathBuf};

use super::parse_activation_dat;
use crate::{KeyError, Result};

/// Directory (relative to `$HOME`) Adobe Digital Editions stores its state in.
const ADE_SUBDIR: &str = "Library/Application Support/Adobe/Digital Editions";
/// The activation file we search for under [`ADE_SUBDIR`].
const ACTIVATION_DAT: &str = "activation.dat";
/// Bound on the recursive search so a pathological tree can't spin forever.
const MAX_SEARCH_DEPTH: usize = 8;

/// Extract every ADEPT user key (DER) from the local `activation.dat`.
pub(super) fn extract_keys() -> Result<Vec<Vec<u8>>> {
    let path = find_activation_dat()?;
    let xml = std::fs::read_to_string(&path)
        .map_err(|e| KeyError::Invalid(format!("read {}: {e}", path.display())))?;
    let keys = parse_activation_dat(&xml)?;
    if keys.is_empty() {
        return Err(KeyError::NotFound(
            "no adept:privateLicenseKey in activation.dat".into(),
        ));
    }
    Ok(keys)
}

/// Locate `activation.dat` under `$HOME/Library/.../Digital Editions`.
///
/// ADE nests it under a per-account subdirectory, so the search is recursive
/// (the `**` in the spec's path), depth-bounded and returning the first match.
fn find_activation_dat() -> Result<PathBuf> {
    let home =
        std::env::var_os("HOME").ok_or_else(|| KeyError::NotFound("HOME is not set".into()))?;
    let root = Path::new(&home).join(ADE_SUBDIR);
    find_named(&root, ACTIVATION_DAT, MAX_SEARCH_DEPTH).ok_or_else(|| {
        KeyError::NotFound(format!(
            "activation.dat not found under {} (is Adobe Digital Editions activated?)",
            root.display()
        ))
    })
}

/// Depth-first search for a file named `name`, returning the first hit.
fn find_named(dir: &Path, name: &str, depth: usize) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut subdirs = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if file_type.is_file() {
            if path.file_name().is_some_and(|n| n == name) {
                return Some(path);
            }
        } else if file_type.is_dir() && depth > 0 {
            subdirs.push(path);
        }
    }
    for sub in subdirs {
        if let Some(found) = find_named(&sub, name, depth - 1) {
            return Some(found);
        }
    }
    None
}
