---
id: TASK-18
title: 'CLI polish: batch mode, auto key-discovery, wired key subcommands'
status: Done
assignee:
  - Kessriga Jeükal
created_date: '2026-07-03 20:00'
updated_date: '2026-07-04 21:17'
labels:
  - cli
milestone: m-5
dependencies:
  - TASK-15
  - TASK-16
  - TASK-17
references:
  - docs/DEDRM_SCHEMES.md
modified_files:
  - crates/flamberge-cli/src/main.rs
  - crates/flamberge-schemes/src/lib.rs
priority: low
ordinal: 18000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Round out the `flamberge` binary. Wire the `keys adobe`/`keys kindle`/`keys kobo` subcommands to the now-implemented extraction (tasks 15-17) instead of returning bail!. Add optional auto key-discovery to `decrypt` (a flag that pulls local Kindle/Adobe/Kobo keys into the KeyStore before trying). Add batch mode: accept a directory or multiple inputs and decrypt each, reporting a per-file summary. Improve dispatch so a non-matching scheme returns NotThisScheme (not a hard error) and the surfaced error is the most relevant one. Ensure no partial output files are left on failure.

Depends on the key-extraction tasks for the subcommand wiring. Spec: docs/DEDRM_SCHEMES.md §0 (dispatch).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 `keys adobe|kindle|kobo` run the real extraction and print/store discovered keys
- [x] #2 `decrypt --auto-keys` (or equivalent) pulls local keys into the KeyStore before attempting decryption
- [x] #3 Batch mode decrypts a directory / multiple files and prints a per-file success/failure summary with a correct exit code
- [x] #4 Non-matching schemes fall through via NotThisScheme; failures never leave a partial output file
- [x] #5 Tests cover batch dispatch and the fall-through/most-relevant-error behavior
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
## Plan

Split the CLI into concern-modules (CLAUDE.md convention) and add batch/auto-keys/kindle wiring.

### Module layout (crates/flamberge-cli/src/)
- `main.rs` — clap `Cli`/`Command`/`DecryptArgs`/`KeysCommand` + top-level dispatch only.
- `naming.rs` — move `default_output`/`cleanup_name`/`is_amazon_download_name`/`is_asin`/`is_uuid` + their tests.
- `decrypt.rs` — single + batch decrypt flow: input expansion, per-file summary, atomic write, `--output`/`--output-dir` rules.
- `keys.rs` — `run_keys` incl. new kindle artifact wiring.
- `autokeys.rs` — best-effort local key gathering for `--auto-keys`.

### AC#1 — keys subcommands (kindle is the gap)
Adobe/Kobo already call real extraction. Wire `keys kindle` to the TASK-15 artifact extraction (on-host `extract_local_keys` stays a stub):
- `--k4i <path>` (repeat): `load_k4i` → print decoded DB entries (`name=hexvalue`).
- `--kinf <path>` (repeat) + `--user-name` + `--id-string` (repeat) + `--platform {mac,windows}`: `decrypt_kinf_candidates` → print DB entries.
- `--android <path>` (repeat): `serials_from_android` → print serials.
- No artifacts supplied → call `extract_local_keys()` (returns Unimplemented) and surface a helpful message pointing at the flags + §6.

### AC#2 — `decrypt --auto-keys`
Best-effort: `autokeys::gather()` runs `adobe::extract_keys` → `adept_keys`, `kobo::discover_userkeys` → `kobo_keys`, `kindle::extract_local_keys` → `kindle_dbs`. Each source's failure (NotFound/Unsupported/Unimplemented) is warned to stderr, never fatal. Merge into the KeyStore before decrypt.

### AC#3 — batch mode
`input: PathBuf` → `inputs: Vec<PathBuf>` (1+). Expand: a directory → its immediate file entries (non-recursive); a file → itself. `--output` allowed only for a single input file; batch uses `--output-dir` (defaults to each input's parent) with `default_output` naming. Decrypt each; print `OK <in> -> <out>` / `FAIL <in>: <err>` / `SKIP <in>: <reason>`; final totals; exit code 1 if any FAIL, error if zero files matched.

### AC#4 — fall-through + no partial output
Dispatch fall-through already lives in `schemes::decrypt` (NotThisScheme = keep looking, else terminal). CLI change: write output via temp-file-in-dest-dir + rename so a failed/interrupted write never leaves a partial file. On decrypt error, nothing is written.

### AC#5 — tests
- `naming.rs`: existing tests move with the fns.
- `decrypt.rs`: `expand_inputs` (dir vs file vs multi) and summary/exit-code formatting are pure helpers → unit tests.
- `schemes` crate: add dispatch tests — unknown extension → `UnknownFormat`; recognized-but-unhandled buffer falls through to `NoKeyWorked`; a terminal scheme error is surfaced (most-relevant-error) rather than masked.

### Verify
`cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, and a manual `flamberge decrypt`/`keys` smoke run.
<!-- SECTION:PLAN:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Rounded out the `flamberge` CLI. Split `flamberge-cli` into concern modules (`main` clap defs + dispatch, `decrypt`, `keys`, `naming`, `autokeys`) per the module-per-concern convention.

**decrypt (batch + safety):** `input: PathBuf` → `inputs: Vec<PathBuf>` accepting one file, several files, or a directory (expanded to its immediate files, non-recursive, sorted). Batch prints a per-file `OK`/`SKIP`/`FAIL` summary and a tally, exits 1 if any file failed; an unsupported extension is a `SKIP` (not a failure), so decrypting a whole folder ignores stray files. `--output` is single-input-only (rejected in batch with a clear message); `--output-dir` targets batch output via the existing title-based naming. Single-file mode prints a plain `Wrote <out>` or a hard error. Every output is written atomically (sibling `.part` temp + rename, temp removed on rename failure) so a failed/interrupted write never leaves a partial file — AC#4.

**--auto-keys:** new flag runs `autokeys::gather`, which best-effort-pulls local Adobe (`adobe::extract_keys`), Kobo (`kobo::discover_userkeys`), and Kindle (`kindle::extract_local_keys`) keys into the `KeyStore` before decrypting; each source's failure (NotFound/Unsupported/Unimplemented) is warned to stderr and skipped, never fatal.

**keys kindle:** wired to the offline TASK-15 extraction instead of `bail!` — decodes `--k4i` databases, decrypts `--kinf` files (with `--user-name` / `--id-string` / `--platform {mac,pc}`), and mines `--android` artifacts for serials, printing decoded DB entries and serials. With no artifact supplied it calls the still-stubbed on-host `extract_local_keys` and surfaces a hint pointing at the flags + §6.

**Dispatch:** the `NotThisScheme` = keep-looking / any-other-error = terminal-and-surfaced behavior already lived in `schemes::decrypt`; added unit tests for it (extension routing, `UnknownFormat`, all-candidates-fall-through → `NoKeyWorked`, terminal error surfaced verbatim).

**Tests:** unit tests for `expand_inputs`, `atomic_write`, and `decrypt_one` (skip on unsupported ext; fail without partial output); dispatch tests in the schemes crate; a new end-to-end `batch_decrypts_directory_and_skips_strays` integration test driving the compiled binary over a synthetic DRMed book + a stray file. Also smoke-tested manually: batch mixed dir, `--output` multi-input rejection, single-file hard error, `keys kindle` (no-artifact hint, validation, real `.k4i` round-trip), and `--auto-keys` best-effort warnings.

Verification: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` (234 tests) all green. Updated CLAUDE.md Status/Next-up to record the polished CLI. Commits: `test(schemes): cover dispatch fall-through...` and `feat(cli): batch mode, auto key-discovery, kindle key wiring (TASK-18)`.

No scope changes. Follow-ups remain as their own tasks: on-host `kindle::extract_local_keys` + Adobe Windows DPAPI, and TASK-19 cross-scheme integration suite.
<!-- SECTION:FINAL_SUMMARY:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 cargo build succeeds with no warnings
- [x] #2 cargo test passes (unit and integration)
- [x] #3 cargo clippy passes with no warnings
- [x] #4 no panic!/unwrap/expect on non-test code paths
- [x] #5 behavior matches docs/DEDRM_SCHEMES.md and code cites the relevant section
- [x] #6 public items have doc comments
<!-- DOD:END -->
