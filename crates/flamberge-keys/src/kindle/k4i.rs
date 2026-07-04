//! `.k4i` key database loading (§6.2).
//!
//! A `.k4i` file is the JSON serialization of a decrypted Kindle DB: a flat
//! object mapping each key name to its **hex-encoded** value
//! (`kindlekey.py::getkey` writes `json.dumps({name: hex(value)})`). This is the
//! portable artifact the Kindle schemes consume, so loading it is just JSON
//! parsing — no crypto.

use super::KindleDb;
use crate::{KeyError, Result};

/// Parse a `.k4i` database from its raw JSON bytes.
///
/// Rejects anything that is not a flat string→string object, since downstream
/// `getK4Pids` reads every value as hex.
pub fn parse_k4i(bytes: &[u8]) -> Result<KindleDb> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| KeyError::Invalid(format!("invalid .k4i JSON: {e}")))?;
    let obj = value
        .as_object()
        .ok_or_else(|| KeyError::Invalid("`.k4i` root is not a JSON object".into()))?;

    let mut db = KindleDb::with_capacity(obj.len());
    for (name, val) in obj {
        let hex = val.as_str().ok_or_else(|| {
            KeyError::Invalid(format!("`.k4i` value for `{name}` is not a string"))
        })?;
        db.insert(name.clone(), hex.to_string());
    }
    Ok(db)
}

/// Load a `.k4i` database from a file on disk.
pub fn load_k4i(path: &std::path::Path) -> Result<KindleDb> {
    let bytes = std::fs::read(path)
        .map_err(|e| KeyError::NotFound(format!("cannot read {}: {e}", path.display())))?;
    parse_k4i(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_flat_hex_map() {
        let json = br#"{"DSN":"aabbccdd","kindle.account.tokens":"0011"}"#;
        let db = parse_k4i(json).unwrap();
        assert_eq!(db.get("DSN"), Some(&"aabbccdd".to_string()));
        assert_eq!(db.get("kindle.account.tokens"), Some(&"0011".to_string()));
        assert_eq!(db.len(), 2);
    }

    #[test]
    fn rejects_non_object_root() {
        assert!(parse_k4i(b"[1,2,3]").is_err());
        assert!(parse_k4i(b"not json").is_err());
    }

    #[test]
    fn rejects_non_string_value() {
        assert!(parse_k4i(br#"{"DSN":123}"#).is_err());
    }
}
