---
id: TASK-23
title: Dedupe Kobo SQLite WAL-patch open helper across keys/schemes
status: In Progress
assignee: []
created_date: '2026-07-04 20:53'
updated_date: '2026-07-05 08:07'
labels:
  - keys
  - schemes
  - kobo
  - cleanup
dependencies: []
references:
  - crates/flamberge-keys/src/kobo/db.rs
  - crates/flamberge-schemes/src/kobo/db.rs
priority: low
ordinal: 23000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up from the TASK-17 code review (PR #18), CONFIRMED finding. The Kobo SQLite "open a WAL DB from bytes" trick is duplicated in two crates:

- `flamberge-keys::kobo::db::open_patched` — patch header bytes 18–19 → `01 01` on a copy, write to a temp file, open read-only. Used by `read_userids`.
- `flamberge-schemes::kobo::db::open_patched` — byte-for-byte the same patch + temp-file + open, used by `read_volume`.

Both exist because `rusqlite` refuses to open a WAL DB without its `-wal` sidecar; the patch forces rollback-journal mode. The two copies can drift: a future fix to the `len >= 20` guard, the `sync_all` semantics, or the header offsets must be edited in both places, and updating only one makes the crates diverge.

**The real decision this task must make is where the shared helper lives**, and it is not obvious:

1. **Hoist into `flamberge-keys`** and have `schemes` call it (the dependency runs `keys ← schemes`, so this compiles). Cheapest, but a generic "open a WAL SQLite from bytes" utility is not conceptually a *key-acquisition* concern, so it sits in a slightly wrong module.
2. **Hoist into `flamberge-formats`** (both `keys` and `schemes` already depend on it — the natural shared home). Conceptually cleanest, but `formats` currently depends on **neither** `rusqlite` nor `tempfile`, so this pulls a SQLite/DB dependency down into the formats crate, widening its dependency surface.

Pick one with a short rationale in the implementation notes. The helper should return the opened `(NamedTempFile, Connection)` (or equivalent) and let each caller run its own query + map to its own error type (`KeyError` vs `SchemeError`), so no error-type coupling is introduced. Keep both callers' existing behaviour and tests green.

Reference: docs/DEDRM_SCHEMES.md §9.1 (WAL header patch).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The WAL-patch + temp-file + read-only-open logic has a single definition shared by both flamberge-keys::kobo::db and flamberge-schemes::kobo::db (no byte-for-byte duplicate)
- [x] #2 The chosen home for the helper is justified in the implementation notes, addressing the keys-vs-formats trade-off (and any new dependency added is recorded)
- [x] #3 Each caller keeps its own query + error-type mapping; no error-type coupling between the crates is introduced
- [x] #4 Existing kobo tests in both crates still pass; cargo build/test/clippy/fmt clean
- [x] #5 No production behaviour change (Kobo discovery and Kobo KEPUB decryption behave identically)
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Hoist the WAL-patch + temp-file + read-only-open logic into flamberge-keys as `kobo::open_kobo_db`, returning `(NamedTempFile, Connection)` and a neutral `KoboDbError` (thiserror). Rationale for keys over formats: keys already depends on rusqlite+tempfile; formats depends on neither, so option 2 would pull bundled-SQLite into the foundational parsing crate. Both call sites are Kobo-specific, so a `open_kobo_db` in keys::kobo is only a mild conceptual stretch.

Steps:
1. In flamberge-keys/src/kobo/db.rs: add `pub fn open_kobo_db(Vec<u8>) -> Result<(NamedTempFile, Connection), KoboDbError>` and `pub enum KoboDbError` (TempFile/Write/Open) with Display strings matching the current messages. Replace the private `open_patched` with a call to it, mapping `e.to_string()` into `KeyError::Invalid`.
2. Re-export from keys kobo/mod.rs: `pub use db::{open_kobo_db, KoboDbError};`.
3. In flamberge-schemes/src/kobo/db.rs: delete local `open_patched`, call `flamberge_keys::kobo::open_kobo_db(db_bytes.to_vec())` mapping `e.to_string()` into the local `invalid(...)`; drop the now-unused `OpenFlags` import.
4. Verify messages preserved exactly; run build/test/clippy/fmt.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Chose **Option 1 — hoisted into `flamberge-keys`** as `kobo::open_kobo_db` (re-exported from `kobo/mod.rs`). Rationale for keys over formats: `flamberge-keys` already depends on `rusqlite` (bundled C SQLite) + `tempfile`, whereas `flamberge-formats` depends on neither. Option 2 (formats) is conceptually the "shared ancestor" home but would pull a bundled-SQLite build down into the foundational parsing crate that every other crate depends on — a real, avoidable compile cost — for a helper both of whose call sites are Kobo-specific. No new dependency was added to any crate; `schemes` already depended on `keys`, so `schemes::kobo::db` calling `flamberge_keys::kobo::open_kobo_db` needs no graph change.

Error decoupling (AC#3): the helper returns a neutral `KoboDbError` (thiserror, variants TempFile/Write/Open) whose `Display` strings reproduce the previous messages verbatim ("temp file for Kobo DB: {e}", "writing Kobo DB copy: {e}", "Kobo DB: {e}"). Each caller maps `e.to_string()` into its own error — keys → `KeyError::Invalid`, schemes → `invalid(...)` → `SchemeError::Format(FormatError::Invalid)` — so neither crate's error enum leaks into the other and the surfaced messages are byte-identical to before (AC#5, no behaviour change).

Removed the duplicate private `open_patched` from both crates; dropped the now-unused `OpenFlags` import from schemes `kobo/db.rs`. keys keeps `read_userids`'s own query + `sqlite_err` mapping; schemes keeps `single_volume`/`read_wrapped_keys`/`read_title` + its own `sqlite_err`/`invalid`. Verified: `cargo fmt --check`, `cargo clippy --workspace --all-targets -D warnings`, and `cargo test --workspace` all clean — both crates' Kobo unit tests plus the `kobo_round_trip` / `kobo_wrong_key_fails_cleanly` integration tests pass.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Deduped the "open a WAL-mode Kobo SQLite DB from an in-memory byte buffer" trick that was copied byte-for-byte in `flamberge-keys::kobo::db` and `flamberge-schemes::kobo::db`.

The logic now lives once as `flamberge_keys::kobo::open_kobo_db(Vec<u8>) -> Result<(NamedTempFile, Connection), KoboDbError>`, chosen over `flamberge-formats` because keys already pays for `rusqlite`+`tempfile` while formats depends on neither (option 2 would push bundled-SQLite into the crate everything depends on). The helper returns a neutral `KoboDbError` so each caller maps it onto its own error type (`KeyError` vs `SchemeError`) with no cross-crate error coupling; the surfaced messages are byte-identical to before, so Kobo discovery and Kobo KEPUB decryption behave identically. Both crates' Kobo tests and the cross-scheme integration round-trips stay green; fmt/clippy(-D warnings)/build/test all clean.
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
