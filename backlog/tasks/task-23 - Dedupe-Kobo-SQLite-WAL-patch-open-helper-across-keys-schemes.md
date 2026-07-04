---
id: TASK-23
title: Dedupe Kobo SQLite WAL-patch open helper across keys/schemes
status: To Do
assignee: []
created_date: '2026-07-04 20:53'
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
- [ ] #1 The WAL-patch + temp-file + read-only-open logic has a single definition shared by both flamberge-keys::kobo::db and flamberge-schemes::kobo::db (no byte-for-byte duplicate)
- [ ] #2 The chosen home for the helper is justified in the implementation notes, addressing the keys-vs-formats trade-off (and any new dependency added is recorded)
- [ ] #3 Each caller keeps its own query + error-type mapping; no error-type coupling between the crates is introduced
- [ ] #4 Existing kobo tests in both crates still pass; cargo build/test/clippy/fmt clean
- [ ] #5 No production behaviour change (Kobo discovery and Kobo KEPUB decryption behave identically)
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 cargo build succeeds with no warnings
- [ ] #2 cargo test passes (unit and integration)
- [ ] #3 cargo clippy passes with no warnings
- [ ] #4 no panic!/unwrap/expect on non-test code paths
- [ ] #5 behavior matches docs/DEDRM_SCHEMES.md and code cites the relevant section
- [ ] #6 public items have doc comments
<!-- DOD:END -->
