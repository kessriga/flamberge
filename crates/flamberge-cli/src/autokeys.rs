//! Best-effort local key discovery for `decrypt --auto-keys`.
//!
//! Pulls whatever the platform-extraction modules can find on this host into the
//! [`KeyStore`] before decryption is attempted. Every source is optional: a
//! missing key store or an unsupported platform is reported to stderr and
//! skipped, never treated as fatal — the user may still have supplied explicit
//! keys, or a later source may succeed. Reference: `docs/DEDRM_SCHEMES.md`
//! §6 (Kindle), §7 (Adobe), §9 (Kobo).

use flamberge_keys::KeyStore;

/// Merge locally discovered Adobe/Kindle/Kobo keys into `keys`, logging each
/// source's outcome to stderr.
pub fn gather(keys: &mut KeyStore) {
    match flamberge_keys::adobe::extract_keys() {
        Ok(found) if !found.is_empty() => {
            eprintln!("auto-keys: {} Adobe ADEPT key(s)", found.len());
            keys.adept_keys.extend(found);
        }
        Ok(_) => eprintln!("auto-keys: no Adobe ADEPT keys on this host"),
        Err(e) => eprintln!("auto-keys: Adobe extraction skipped ({e})"),
    }

    // Kobo needs both the derived user keys *and* the library DB (the per-file
    // page keys live in the DB, not the book), so populate both from one scan.
    // Don't clobber a DB the user passed explicitly with `--kobo-db`.
    match flamberge_keys::kobo::discover() {
        Ok(found) if !found.user_keys.is_empty() => {
            eprintln!(
                "auto-keys: {} candidate Kobo user key(s) + library DB",
                found.user_keys.len()
            );
            keys.kobo_keys.extend(found.user_keys);
            if keys.kobo_db.is_none() {
                keys.kobo_db = Some(found.db);
            }
        }
        Ok(_) => eprintln!("auto-keys: no Kobo user keys derivable on this host"),
        Err(e) => eprintln!("auto-keys: Kobo discovery skipped ({e})"),
    }

    match flamberge_keys::kindle::extract_local_keys() {
        Ok(found) if !found.is_empty() => {
            eprintln!("auto-keys: {} Kindle key database(s)", found.len());
            keys.kindle_dbs.extend(found);
        }
        Ok(_) => eprintln!("auto-keys: no Kindle key databases on this host"),
        Err(e) => eprintln!("auto-keys: Kindle extraction skipped ({e})"),
    }
}
