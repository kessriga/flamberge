//! The `decrypt` subcommand: single-file and batch DRM removal.
//!
//! Dispatch itself lives in `flamberge_schemes::decrypt` (extension → candidate
//! schemes, each tried until one claims the file). This module drives it: it
//! assembles the [`KeyStore`] from the CLI flags (plus optional `--auto-keys`
//! host discovery), expands directory/multi-file inputs, writes each output
//! atomically so a failure never leaves a partial file, and prints a per-file
//! summary. Reference: `docs/DEDRM_SCHEMES.md` §0 (dispatch).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use flamberge_keys::KeyStore;
use flamberge_schemes::SchemeError;

use crate::{autokeys, naming, DecryptArgs};

/// Entry point for `flamberge decrypt`.
pub fn run(args: DecryptArgs) -> Result<()> {
    let keys = build_keystore(&args)?;
    let files = expand_inputs(&args.inputs)?;
    if files.is_empty() {
        bail!("no input files found");
    }

    // `--output` names a single destination, so it is meaningful only for a lone
    // input file; batch runs use `--output-dir` (or each input's own parent).
    let single = files.len() == 1;
    if args.output.is_some() && !single {
        bail!("--output is only valid for a single input file; use --output-dir for batch runs");
    }

    let out_dir = args.output_dir.as_deref();

    // Single explicit input: print a plain success line, or surface a
    // skip/failure as a hard error so the exit code and message are unambiguous
    // (no redundant per-file report line).
    if single {
        let file = &files[0];
        return match decrypt_one(file, &keys, args.output.as_deref(), out_dir) {
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
        let outcome = decrypt_one(file, &keys, args.output.as_deref(), out_dir);
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

/// Expand the input list into a flat, sorted list of files: a directory becomes
/// its immediate file entries (non-recursive); a file is taken as-is.
fn expand_inputs(inputs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for path in inputs {
        let meta = fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
        if meta.is_dir() {
            for entry in
                fs::read_dir(path).with_context(|| format!("listing {}", path.display()))?
            {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    files.push(entry.path());
                }
            }
        } else {
            files.push(path.clone());
        }
    }
    files.sort();
    Ok(files)
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
        fs::create_dir(dir.join("sub")).unwrap();
        fs::write(dir.join("sub/deep.pdf"), b"x").unwrap(); // nested: not included

        let files = expand_inputs(std::slice::from_ref(&dir)).unwrap();
        let names: Vec<_> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        // Sorted, immediate files only (subdir contents excluded).
        assert_eq!(names, vec!["a.mobi", "b.epub"]);

        // A plain file passes straight through.
        let one = expand_inputs(&[dir.join("a.mobi")]).unwrap();
        assert_eq!(one, vec![dir.join("a.mobi")]);

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

        let outcome = decrypt_one(&input, &keys, None, None);
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

        let outcome = decrypt_one(&input, &keys, None, None);
        assert!(matches!(outcome, Outcome::Failed(_)));
        let entries: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("broken.mobi")]);
        let _ = fs::remove_dir_all(&dir);
    }
}
