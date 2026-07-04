//! The `decrypt` subcommand: single-file and batch DRM removal.
//!
//! Dispatch itself lives in `flamberge_schemes::decrypt` (extension → candidate
//! schemes, each tried until one claims the file). This module drives it: it
//! assembles the [`KeyStore`] from the CLI flags (plus optional `--auto-keys`
//! host discovery), expands directory/multi-file inputs, writes each output
//! atomically so a failure never leaves a partial file, and prints a per-file
//! summary. Reference: `docs/DEDRM_SCHEMES.md` §0 (dispatch).

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use flamberge_keys::KeyStore;
use flamberge_schemes::SchemeError;

use crate::{autokeys, naming, DecryptArgs};

/// Entry point for `flamberge decrypt`.
pub fn run(args: DecryptArgs) -> Result<()> {
    if args.output.is_some() && args.output_dir.is_some() {
        bail!("--output and --output-dir are mutually exclusive");
    }

    let keys = build_keystore(&args)?;
    let (files, saw_directory) = expand_inputs(&args.inputs)?;
    if files.is_empty() {
        bail!("no input files found");
    }

    // "Batch" is decided by intent — multiple inputs, or a directory to scan —
    // not by how many files a lone directory happened to hold. So a folder with
    // a single stray file still *skips* it rather than erroring, and `--output`
    // (a single destination) is rejected the moment a directory is involved.
    let batch = args.inputs.len() > 1 || saw_directory;
    if args.output.is_some() && batch {
        bail!("--output is only valid for a single input file; use --output-dir for batch runs");
    }

    let out_dir = args.output_dir.as_deref();
    if let Some(dir) = out_dir {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }

    // `seen` guards against two inputs resolving to the same output path (e.g.
    // same-named books from different folders under one `--output-dir`); the
    // second is failed rather than silently overwriting the first.
    let mut seen = HashSet::new();

    // Single explicit input: print a plain success line, or surface a
    // skip/failure as a hard error so the exit code and message are unambiguous
    // (no redundant per-file report line).
    if !batch {
        let file = &files[0];
        return match decrypt_one(file, &keys, args.output.as_deref(), out_dir, &mut seen) {
            Outcome::Written(out) => {
                println!("Wrote {}", out.display());
                Ok(())
            }
            Outcome::Skipped(reason) => Err(anyhow!("{}: {reason}", file.display())),
            Outcome::Failed(err) => Err(anyhow!("{}: {err}", file.display())),
        };
    }

    // Batch: report each file, then a tally; fail the run if any file failed.
    let mut tally = Tally::default();
    for file in &files {
        let outcome = decrypt_one(file, &keys, args.output.as_deref(), out_dir, &mut seen);
        report(file, &outcome);
        tally.record(&outcome);
    }
    println!(
        "\n{} ok, {} failed, {} skipped ({} file(s))",
        tally.ok,
        tally.failed,
        tally.skipped,
        files.len()
    );
    if tally.failed > 0 {
        bail!("{} of {} file(s) failed", tally.failed, files.len());
    }
    Ok(())
}

/// What happened to one input file.
enum Outcome {
    /// Decrypted and written to this path.
    Written(PathBuf),
    /// Not an ebook we handle (unknown/unsupported extension); left untouched.
    Skipped(String),
    /// Recognized but decryption failed.
    Failed(String),
}

#[derive(Default)]
struct Tally {
    ok: usize,
    failed: usize,
    skipped: usize,
}

impl Tally {
    fn record(&mut self, outcome: &Outcome) {
        match outcome {
            Outcome::Written(_) => self.ok += 1,
            Outcome::Skipped(_) => self.skipped += 1,
            Outcome::Failed(_) => self.failed += 1,
        }
    }
}

fn report(input: &Path, outcome: &Outcome) {
    match outcome {
        Outcome::Written(out) => println!("OK   {} -> {}", input.display(), out.display()),
        Outcome::Skipped(reason) => println!("SKIP {}: {reason}", input.display()),
        Outcome::Failed(err) => println!("FAIL {}: {err}", input.display()),
    }
}

/// Decrypt a single file. Never propagates the decryption error (so a batch keeps
/// going); classifies it into an [`Outcome`] instead. An unsupported extension is
/// a *skip* (not a failure), so decrypting a whole directory ignores stray files.
fn decrypt_one(
    input: &Path,
    keys: &KeyStore,
    explicit_out: Option<&Path>,
    out_dir: Option<&Path>,
    seen: &mut HashSet<PathBuf>,
) -> Outcome {
    let data = match fs::read(input) {
        Ok(d) => d,
        Err(e) => return Outcome::Failed(format!("reading input: {e}")),
    };
    let ext = input
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();

    let book = match flamberge_schemes::decrypt(&data, ext, keys) {
        Ok(b) => b,
        Err(SchemeError::UnknownFormat(_)) => return Outcome::Skipped("unsupported format".into()),
        Err(e) => return Outcome::Failed(e.to_string()),
    };

    let out = match explicit_out {
        Some(p) => p.to_path_buf(),
        None => naming::default_output(input, &book.extension, book.title.as_deref(), out_dir),
    };
    // Refuse to overwrite an output another input already produced this run.
    if !seen.insert(out.clone()) {
        return Outcome::Failed(format!(
            "output path {} collides with an earlier input in this run",
            out.display()
        ));
    }
    match atomic_write(&out, &book.data) {
        Ok(()) => Outcome::Written(out),
        Err(e) => Outcome::Failed(format!("writing output: {e}")),
    }
}

/// Assemble the [`KeyStore`] from the CLI flags, then optionally augment it with
/// host-discovered keys when `--auto-keys` was given.
fn build_keystore(args: &DecryptArgs) -> Result<KeyStore> {
    let mut keys = KeyStore::new();
    keys.pids = args.pid.clone();
    keys.serials = args.serial.clone();
    keys.bandn_keys = args.bandn_key.clone();
    for path in &args.adept_key {
        keys.adept_keys
            .push(fs::read(path).with_context(|| format!("reading {}", path.display()))?);
    }
    for hexkey in &args.ereader_key {
        let bytes = hex::decode(hexkey).context("eReader key must be hex")?;
        let arr: [u8; 8] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("eReader key must be 8 bytes"))?;
        keys.ereader_keys.push(arr);
    }
    for hexkey in &args.kobo_key {
        let bytes = hex::decode(hexkey).context("Kobo key must be hex")?;
        let arr: [u8; 16] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Kobo key must be 16 bytes"))?;
        keys.kobo_keys.push(arr);
    }
    if let Some(path) = &args.kobo_db {
        keys.kobo_db = Some(fs::read(path).with_context(|| format!("reading {}", path.display()))?);
    }
    keys.kobo_volumeid = args.kobo_volumeid.clone();
    for path in &args.k4i {
        keys.kindle_dbs.push(
            flamberge_keys::kindle::load_k4i(path)
                .with_context(|| format!("loading .k4i {}", path.display()))?,
        );
    }
    for path in &args.android {
        keys.serials.extend(
            flamberge_keys::kindle::serials_from_android(path)
                .with_context(|| format!("extracting serials from {}", path.display()))?,
        );
    }

    if args.auto_keys {
        autokeys::gather(&mut keys);
    }
    Ok(keys)
}

/// Expand the input list into a flat, sorted list of files, reporting whether any
/// input was a directory. A directory becomes its immediate file entries
/// (non-recursive), skipping files we ourselves produced (`*_nodrm.*`) so that
/// re-running over a folder does not try to "decrypt" already-decrypted output.
/// An explicitly named file is always taken as-is (never suffix-filtered).
fn expand_inputs(inputs: &[PathBuf]) -> Result<(Vec<PathBuf>, bool)> {
    let mut files = Vec::new();
    let mut saw_directory = false;
    for path in inputs {
        let meta = fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
        if meta.is_dir() {
            saw_directory = true;
            for entry in
                fs::read_dir(path).with_context(|| format!("listing {}", path.display()))?
            {
                let entry = entry?;
                let entry_path = entry.path();
                if entry.file_type()?.is_file() && !is_nodrm_output(&entry_path) {
                    files.push(entry_path);
                }
            }
        } else {
            files.push(path.clone());
        }
    }
    files.sort();
    Ok((files, saw_directory))
}

/// True if `path` looks like one of our own decrypted outputs (stem ends in
/// `_nodrm`), so a directory scan can skip it.
fn is_nodrm_output(path: &Path) -> bool {
    path.file_stem()
        .and_then(|s| s.to_str())
        .is_some_and(|s| s.ends_with("_nodrm"))
}

/// Write `data` to `dest` atomically: write a sibling `.part` file, then rename
/// it over the destination. A crash or I/O error mid-write leaves only the temp
/// file (which is removed on rename failure), never a truncated output.
fn atomic_write(dest: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = tmp_path(dest);
    fs::write(&tmp, data)?;
    if let Err(e) = fs::rename(&tmp, dest) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Sibling temp path for the atomic write (`<dest>.part`).
fn tmp_path(dest: &Path) -> PathBuf {
    let mut name = dest.file_name().unwrap_or_default().to_os_string();
    name.push(".part");
    dest.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> PathBuf {
        let base = std::env::temp_dir().join(format!("flamberge-test-{}", std::process::id()));
        // Unique-ish per call via an atomic counter.
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = base.join(N.fetch_add(1, Ordering::Relaxed).to_string());
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn expand_inputs_flattens_dir_and_keeps_files() {
        let dir = tmp_dir();
        fs::write(dir.join("b.epub"), b"x").unwrap();
        fs::write(dir.join("a.mobi"), b"x").unwrap();
        fs::write(dir.join("a_nodrm.mobi"), b"x").unwrap(); // our own output: skipped
        fs::create_dir(dir.join("sub")).unwrap();
        fs::write(dir.join("sub/deep.pdf"), b"x").unwrap(); // nested: not included

        let (files, saw_dir) = expand_inputs(std::slice::from_ref(&dir)).unwrap();
        assert!(saw_dir);
        let names: Vec<_> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        // Sorted, immediate files only; subdir contents and `_nodrm` outputs excluded.
        assert_eq!(names, vec!["a.mobi", "b.epub"]);

        // A plain file passes straight through and is *not* flagged as a directory,
        // even if it is itself a `_nodrm` file (explicit inputs are never filtered).
        let (one, saw_dir) = expand_inputs(&[dir.join("a_nodrm.mobi")]).unwrap();
        assert_eq!(one, vec![dir.join("a_nodrm.mobi")]);
        assert!(!saw_dir);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn expand_inputs_reports_missing_path() {
        let err = expand_inputs(&[PathBuf::from("/no/such/path/here.mobi")]).unwrap_err();
        assert!(err.to_string().contains("here.mobi"));
    }

    #[test]
    fn atomic_write_leaves_no_part_file_on_success() {
        let dir = tmp_dir();
        let dest = dir.join("out.epub");
        atomic_write(&dest, b"payload").unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"payload");
        assert!(!tmp_path(&dest).exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn decrypt_one_skips_unsupported_extension() {
        let dir = tmp_dir();
        let input = dir.join("notes.txt");
        fs::write(&input, b"just text").unwrap();
        let keys = KeyStore::new();

        let outcome = decrypt_one(&input, &keys, None, None, &mut HashSet::new());
        assert!(matches!(outcome, Outcome::Skipped(_)));
        // Nothing written.
        assert!(!dir.join("notes_nodrm.txt").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn decrypt_one_fails_without_partial_output() {
        // A `.mobi` that is too short to be a PalmDB fails terminally; no output
        // file (or leftover temp) may be produced.
        let dir = tmp_dir();
        let input = dir.join("broken.mobi");
        fs::write(&input, b"short").unwrap();
        let keys = KeyStore::new();

        let outcome = decrypt_one(&input, &keys, None, None, &mut HashSet::new());
        assert!(matches!(outcome, Outcome::Failed(_)));
        let entries: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("broken.mobi")]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn is_nodrm_output_matches_only_our_suffix() {
        assert!(is_nodrm_output(Path::new("book_nodrm.epub")));
        assert!(is_nodrm_output(Path::new("/a/b/Great Read_nodrm.mobi")));
        assert!(!is_nodrm_output(Path::new("book.epub")));
        assert!(!is_nodrm_output(Path::new("nodrm.epub")));
    }
}
