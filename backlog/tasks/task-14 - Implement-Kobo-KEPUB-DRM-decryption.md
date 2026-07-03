---
id: TASK-14
title: Implement Kobo (KEPUB) DRM decryption
status: To Do
assignee: []
created_date: '2026-07-03 19:59'
labels:
  - schemes
  - kobo
milestone: m-3
dependencies: []
references:
  - docs/DEDRM_SCHEMES.md
  - ../../external/DeDRM_tools/Obok_plugin/obok/obok.py
modified_files:
  - crates/flamberge-schemes/src/kobo.rs
  - crates/flamberge-keys/src/kobo.rs
priority: low
ordinal: 14000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement flamberge-schemes::kobo. Read per-file page keys from the Kobo SQLite DB (`content_keys`/`content`: elementid = zip path, elementkey = base64 AES-wrapped page key) — add a `rusqlite` (bundled) dependency. Decrypt with the two-layer AES-128-ECB (§9.3): page_key = AES-ECB-decrypt(user_key, base64decode(elementkey)); plaintext = AES-ECB-decrypt(page_key, contents); then strip CMS/PKCS#7 padding. Candidate user keys come from flamberge-keys::kobo::derive_userkeys. Use `check()`-style content validation (xhtml printable-ASCII after BOM; jpeg FF D8 FF) to select the right key by trial, then repackage the KEPUB as an EPUB (deflated). Handle the WAL header patch (bytes 18-19 -> 01 01) when opening the DB copy. Original: obok.py.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Per-file page keys are read from content_keys/content in the Kobo SQLite DB (with the WAL header workaround on a temp copy)
- [ ] #2 Two-layer AES-128-ECB decrypt (user key -> page key -> contents) + CMS/PKCS#7 padding strip yields plaintext
- [ ] #3 The correct user key is found by trial using content validation (xhtml/jpeg sniffing); DRM-free files are copied
- [ ] #4 Output is a repackaged EPUB; a book with no working key fails clearly
- [ ] #5 Integration test decrypts a synthesized KEPUB + minimal SQLite DB with a derive_userkeys candidate and asserts content
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
