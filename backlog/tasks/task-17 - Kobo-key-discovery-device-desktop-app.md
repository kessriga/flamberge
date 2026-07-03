---
id: TASK-17
title: Kobo key discovery (device + desktop app)
status: To Do
assignee: []
created_date: '2026-07-03 20:00'
labels:
  - keys
  - kobo
milestone: m-4
dependencies: []
references:
  - docs/DEDRM_SCHEMES.md
  - ../../external/DeDRM_tools/Obok_plugin/obok/obok.py
modified_files:
  - crates/flamberge-keys/src/kobo.rs
priority: low
ordinal: 17000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement flamberge-keys::kobo::discover_userkeys: locate the Kobo library DB (device `.kobo/KoboReader.sqlite` or desktop `Kobo.sqlite` per-OS), read `UserID`s from the `user` table, enumerate host MAC addresses and the device serial (from `.adobe-digital-editions/device.xml`), then feed them into the already-implemented derive_userkeys to produce candidate 16-byte keys. Handle the SQLite WAL header workaround. Return keys into KeyStore.kobo_keys. Spec: docs/DEDRM_SCHEMES.md §9.1–9.2. Original: obok.py (KoboLibrary).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Locates the Kobo DB on the current OS (device and desktop paths) and reads UserIDs
- [ ] #2 Enumerates host MAC addresses and, when present, the device serial from device.xml
- [ ] #3 Feeds inputs into derive_userkeys and returns candidate keys into KeyStore.kobo_keys
- [ ] #4 Missing DB / no inputs returns a clear NotFound error rather than a panic
- [ ] #5 Unit test drives derive inputs from a fixture DB and asserts a non-empty candidate set
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
