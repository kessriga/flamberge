//! Reading `UserID`s from the Kobo library SQLite database (§9.1–9.2).
//!
//! The DB may be in WAL mode, which SQLite refuses to open without its sidecar
//! `-wal` file. [`open_kobo_db`] patches the header of a copy (bytes 18–19 →
//! `01 01`, forcing rollback-journal mode) and opens that copy read-only from a
//! temp file; it is shared with the Kobo scheme in `flamberge-schemes`, which
//! calls it for the same reason (the per-file wrapped page keys live in the DB).
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §9.1–9.2; obok `__getuserids`.

use std::io::Write;

use rusqlite::{Connection, OpenFlags};
use tempfile::NamedTempFile;

use crate::{KeyError, Result};

/// Failure opening a Kobo SQLite DB from raw bytes via [`open_kobo_db`].
///
/// A neutral error so each caller maps it onto its own error type without
/// coupling the `flamberge-keys` and `flamberge-schemes` error enums together.
#[derive(Debug, thiserror::Error)]
pub enum KoboDbError {
    /// Creating the backing temp file failed.
    #[error("temp file for Kobo DB: {0}")]
    TempFile(#[source] std::io::Error),
    /// Writing the patched DB bytes to the temp file failed.
    #[error("writing Kobo DB copy: {0}")]
    Write(#[source] std::io::Error),
    /// SQLite could not open the patched copy.
    #[error("Kobo DB: {0}")]
    Open(#[source] rusqlite::Error),
}

/// Open a Kobo library SQLite database supplied as raw `db_bytes`, read-only.
///
/// The DB may be in WAL mode, which SQLite refuses to open without its sidecar
/// `-wal` file. Following obok (`KoboLibrary.__init__`), the header is patched
/// (bytes 18–19 → `01 01`, forcing rollback-journal mode) and a temp-file copy
/// is opened read-only. Consumes `db_bytes`, patching it in place so the
/// (potentially large) buffer is not copied again.
///
/// Returns the temp-file guard alongside the connection: the file must outlive
/// the connection, so keep the guard bound until every query has run. Shared
/// with the Kobo scheme in `flamberge-schemes`; each caller maps [`KoboDbError`]
/// onto its own error type.
///
/// Reference: `docs/DEDRM_SCHEMES.md` §9.1 (WAL header patch).
pub fn open_kobo_db(
    mut db_bytes: Vec<u8>,
) -> std::result::Result<(NamedTempFile, Connection), KoboDbError> {
    // Force rollback-journal mode so SQLite opens the copy without a -wal file.
    if db_bytes.len() >= 20 {
        db_bytes[18] = 0x01;
        db_bytes[19] = 0x01;
    }

    let mut file = NamedTempFile::new().map_err(KoboDbError::TempFile)?;
    file.write_all(&db_bytes)
        .and_then(|()| file.as_file().sync_all())
        .map_err(KoboDbError::Write)?;

    let conn = Connection::open_with_flags(file.path(), OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(KoboDbError::Open)?;
    Ok((file, conn))
}

/// Read every `UserID` from the `user` table of the Kobo DB `db_bytes`.
///
/// Rows whose `UserID` is NULL or non-text are skipped (obok wraps the read in
/// try/except for the same reason); empty-string ids are kept, matching obok's
/// unconditional append. Takes `db_bytes` by value so the (potentially large)
/// buffer is patched in place rather than copied. The returned ids feed the key
/// derivation in [`super::derive_userkeys`].
pub(super) fn read_userids(db_bytes: Vec<u8>) -> Result<Vec<String>> {
    // The temp file must outlive the connection; both are dropped at end of fn.
    let (_tmp, conn) = open_kobo_db(db_bytes).map_err(|e| KeyError::Invalid(e.to_string()))?;
    let mut stmt = conn
        .prepare("SELECT UserID FROM user")
        .map_err(sqlite_err)?;
    let userids: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_err)?
        .filter_map(|r| r.ok())
        .collect();
    Ok(userids)
}

fn sqlite_err(e: rusqlite::Error) -> KeyError {
    KeyError::Invalid(format!("Kobo DB: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal Kobo-shaped SQLite DB in a temp file and return its raw
    /// bytes, so `read_userids` can be exercised without a real device.
    fn fixture_db(userids: &[&str]) -> Vec<u8> {
        let file = tempfile::NamedTempFile::new().unwrap();
        {
            let conn = Connection::open(file.path()).unwrap();
            conn.execute("CREATE TABLE user (UserID TEXT)", []).unwrap();
            for id in userids {
                conn.execute("INSERT INTO user (UserID) VALUES (?1)", [id])
                    .unwrap();
            }
        }
        std::fs::read(file.path()).unwrap()
    }

    #[test]
    fn reads_userids_from_fixture() {
        let db = fixture_db(&[
            "11111111-2222-3333-4444-555555555555",
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        ]);
        let ids = read_userids(db).unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"11111111-2222-3333-4444-555555555555".to_string()));
    }

    #[test]
    fn skips_null_userids_but_keeps_the_rest() {
        // NULL rows are dropped (obok's try/except), but a real id is kept.
        let file = tempfile::NamedTempFile::new().unwrap();
        {
            let conn = Connection::open(file.path()).unwrap();
            conn.execute("CREATE TABLE user (UserID TEXT)", []).unwrap();
            conn.execute("INSERT INTO user (UserID) VALUES (NULL)", [])
                .unwrap();
            conn.execute("INSERT INTO user (UserID) VALUES ('real-id')", [])
                .unwrap();
        }
        let db = std::fs::read(file.path()).unwrap();
        let ids = read_userids(db).unwrap();
        assert_eq!(ids, vec!["real-id".to_string()]);
    }

    #[test]
    fn missing_table_is_an_error_not_a_panic() {
        let file = tempfile::NamedTempFile::new().unwrap();
        {
            let conn = Connection::open(file.path()).unwrap();
            conn.execute("CREATE TABLE other (x TEXT)", []).unwrap();
        }
        let db = std::fs::read(file.path()).unwrap();
        assert!(read_userids(db).is_err());
    }
}
