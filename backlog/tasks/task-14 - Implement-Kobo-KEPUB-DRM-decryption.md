---
id: TASK-14
title: Implement Kobo (KEPUB) DRM decryption
status: In Progress
assignee:
  - Kessriga Jeükal
created_date: '2026-07-03 19:59'
updated_date: '2026-07-04 11:18'
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

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
## Approach (§9, obok.py)

**Interface gap:** per-file page keys live in the external Kobo SQLite DB, not in the book or the user-key set. Thread the DB into the scheme via new `KeyStore` fields.

1. **Deps:** add `rusqlite` (features=["bundled"]) + `tempfile` to workspace + `flamberge-schemes`. Add `aes::ecb_encrypt` to `flamberge-crypto` (round-trip partner, needed by tests; mirrors the DES ecb_encrypt partner). Separate commit.
2. **KeyStore** (`flamberge-keys`): add `kobo_db: Option<Vec<u8>>` (raw sqlite bytes) and `kobo_volumeid: Option<String>`.
3. **Scheme** — convert `kobo.rs` → `kobo/` dir (module-per-concern, like `ereader/`):
   - `db.rs`: WAL header patch (bytes 18–19 → 01 01) on a temp copy, open with rusqlite read-only, query `SELECT elementid, elementkey FROM content_keys, content WHERE volumeid=?1 AND volumeid=contentid`, base64-decode elementkey → `Vec<{elementid, wrapped}>`. volumeid = provided or the single distinct volume in the DB (else clear error). Also fetch volume Title for output naming.
   - `content.rs`: `page_key = AES-ECB-dec(user_key, wrapped)` → `plain = AES-ECB-dec(page_key, contents)` → strip CMS/PKCS#7 padding (faithful port of `__removeaespadding`). `check()` by elementid extension: xhtml/html/xml → first 5 chars printable ASCII after BOM; jpg/jpeg → FF D8 FF; else unchecked.
   - `mod.rs`: detect zip magic (else NotThisScheme); require `kobo_db` (else clear error); read members via `ocf::read_all_members`; per candidate `keys.kobo_keys`: decrypt each encrypted member + `check()`; accept the key where no checkable file fails; repackage via `ocf::repackage` (mimetype-first stored + deflate rest) → `.epub`.
4. **CLI:** `--kobo-db <path>`, `--kobo-volumeid <id>`, `--kobo-key <32hex>` (repeatable).
5. **Tests:** unit (padding strip, check sniffing, single-file 2-layer round-trip) + integration (synth kepub zip + synth sqlite DB, key from `derive_userkeys`, decrypt → assert plaintext + repackaged epub). "No working key" → `NoKeyWorked`.
6. Verify build/test/clippy/fmt; update CLAUDE.md Status; PR.
<!-- SECTION:PLAN:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 cargo build succeeds with no warnings
- [ ] #2 cargo test passes (unit and integration)
- [ ] #3 cargo clippy passes with no warnings
- [ ] #4 no panic!/unwrap/expect on non-test code paths
- [ ] #5 behavior matches docs/DEDRM_SCHEMES.md and code cites the relevant section
- [ ] #6 public items have doc comments
<!-- DOD:END -->
