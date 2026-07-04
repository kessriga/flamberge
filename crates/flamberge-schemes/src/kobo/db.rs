//! Reading the Kobo library SQLite database (§9.1 / §9.3).
//!
//! The DB may be in WAL mode, which SQLite refuses to open without its sidecar
//! `-wal` file. Following `obok.py` (`KoboLibrary.__init__`), we patch the
//! header of a copy (bytes 18–19 → `01 01`, forcing rollback-journal mode) and
//! open that copy from a temp file read-only. The per-file wrapped page keys and
//! the book title are read from `content_keys` joined with `content`.

use base64::Engine;
use rusqlite::{Connection, OpenFlags};

use crate::{Result, SchemeError};

/// One encrypted member as recorded in the DB: the zip-internal path
/// (`elementid`) and its base64-decoded AES-wrapped 16-byte page key.
pub(super) struct WrappedKey {
    pub elementid: String,
    pub wrapped: Vec<u8>,
}

/// Everything the scheme reads from the DB for one volume.
pub(super) struct VolumeKeys {
    pub keys: Vec<WrappedKey>,
    pub title: Option<String>,
}

/// Read the wrapped page keys (and title) for `volumeid`, or for the single
/// volume in the DB when `volumeid` is `None`.
pub(super) fn read_volume(db_bytes: &[u8], volumeid: Option<&str>) -> Result<VolumeKeys> {
    // The temp file must outlive the connection: it is bound (not dropped) until
    // the end of this function, after all queries have run.
    let (_tmp, conn) = open_patched(db_bytes)?;

    let vid = match volumeid {
        Some(v) => v.to_string(),
        None => single_volume(&conn)?,
    };
    let keys = read_wrapped_keys(&conn, &vid)?;
    if keys.is_empty() {
        return Err(invalid(format!(
            "the Kobo DB has no content keys for volume {vid}"
        )));
    }
    let title = read_title(&conn, &vid);
    Ok(VolumeKeys { keys, title })
}

/// Write the WAL-patched DB bytes to a temp file and open it read-only. Returns
/// the temp-file guard alongside the connection so the caller keeps the backing
/// file alive.
fn open_patched(db_bytes: &[u8]) -> Result<(tempfile::NamedTempFile, Connection)> {
    use std::io::Write;

    let mut patched = db_bytes.to_vec();
    // Force rollback-journal mode so SQLite opens the copy without a -wal file.
    if patched.len() >= 20 {
        patched[18] = 0x01;
        patched[19] = 0x01;
    }

    let mut file = tempfile::NamedTempFile::new()
        .map_err(|e| invalid(format!("temp file for Kobo DB: {e}")))?;
    file.write_all(&patched)
        .and_then(|()| file.as_file().sync_all())
        .map_err(|e| invalid(format!("writing Kobo DB copy: {e}")))?;

    let conn = Connection::open_with_flags(file.path(), OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(sqlite_err)?;
    Ok((file, conn))
}

/// The single distinct `volumeid` in the library, or a clear error when the DB
/// holds none or several (in which case the caller must disambiguate). Joins
/// `content` exactly as obok's book enumeration does, so a stale `content_keys`
/// row for a volume no longer in `content` does not count as a second book.
fn single_volume(conn: &Connection) -> Result<String> {
    let mut stmt = conn
        .prepare(
            "SELECT DISTINCT volumeid FROM content_keys, content \
             WHERE volumeid = contentid",
        )
        .map_err(sqlite_err)?;
    let mut volumes: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_err)?
        .collect::<rusqlite::Result<_>>()
        .map_err(sqlite_err)?;
    match volumes.len() {
        1 => Ok(volumes.remove(0)),
        0 => Err(invalid("the Kobo DB has no encrypted volumes")),
        _ => Err(invalid(
            "the Kobo DB has multiple volumes; specify the volume id",
        )),
    }
}

/// Query the wrapped page keys for one volume, base64-decoding each key. Mirrors
/// obok's `encryptedfiles` query, joining `content` so only volumes present in
/// the library are decrypted.
fn read_wrapped_keys(conn: &Connection, vid: &str) -> Result<Vec<WrappedKey>> {
    let mut stmt = conn
        .prepare(
            "SELECT elementid, elementkey FROM content_keys, content \
             WHERE volumeid = ?1 AND volumeid = contentid",
        )
        .map_err(sqlite_err)?;
    let rows = stmt
        .query_map([vid], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(sqlite_err)?;

    let mut keys = Vec::new();
    for row in rows {
        let (elementid, elementkey_b64) = row.map_err(sqlite_err)?;
        let wrapped = base64::engine::general_purpose::STANDARD
            .decode(elementkey_b64.trim())
            .map_err(|e| invalid(format!("invalid base64 page key for {elementid}: {e}")))?;
        keys.push(WrappedKey { elementid, wrapped });
    }
    Ok(keys)
}

/// The book's display title (`content.Title`), if present and non-empty.
fn read_title(conn: &Connection, vid: &str) -> Option<String> {
    conn.query_row(
        "SELECT Title FROM content WHERE contentid = ?1",
        [vid],
        |row| row.get::<_, Option<String>>(0),
    )
    .ok()
    .flatten()
    .filter(|t| !t.is_empty())
}

fn sqlite_err(e: rusqlite::Error) -> SchemeError {
    invalid(format!("Kobo DB: {e}"))
}

fn invalid(msg: impl Into<String>) -> SchemeError {
    SchemeError::Format(flamberge_formats::FormatError::Invalid(msg.into()))
}
