---
id: TASK-8
title: Implement OCF/EPUB reader + writer
status: Done
assignee: []
created_date: '2026-07-03 19:57'
updated_date: '2026-07-04 08:16'
labels:
  - formats
  - epub
  - adept
  - ignoble
milestone: m-2
dependencies: []
references:
  - docs/DEDRM_SCHEMES.md
  - ../../external/DeDRM_tools/DeDRM_plugin/ineptepub.py
  - ../../external/DeDRM_tools/DeDRM_plugin/ignobleepub.py
modified_files:
  - crates/flamberge-formats/src/ocf.rs
  - CLAUDE.md
priority: medium
ordinal: 8000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement flamberge-formats::ocf, the shared EPUB layer for both Adobe ADEPT and B&N ignoble. Read `META-INF/rights.xml` (extract the base64 `adept:encryptedKey` text) and `META-INF/encryption.xml` (collect the set of encrypted file paths from `enc:CipherReference@URI`). Provide a detector for ADEPT vs B&N (both present these files; disambiguate by the wrapped-key length: 172 chars = ADEPT/1024-bit RSA, 64 chars = B&N). Provide a repackaging writer that emits a new zip with `mimetype` stored first (ZIP_STORED) and the rest deflated, preserving entry metadata, dropping rights.xml/encryption.xml, and replacing decrypted members.

This is I/O + XML only; the crypto lives in the scheme tasks. Spec: docs/DEDRM_SCHEMES.md §4.4 / §7.3. Original: ineptepub.py, ignobleepub.py.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Parses rights.xml/encryption.xml and exposes the wrapped-key base64 and the encrypted-path set
- [x] #2 Detects ADEPT vs B&N by wrapped-key length (172 vs 64) and reports 'not encrypted' when the META-INF files are absent
- [x] #3 Repackaging writer emits mimetype first + stored, deflates other members, preserves entry metadata, and omits rights.xml/encryption.xml
- [x] #4 Round-trip test: read a synthetic encrypted EPUB, replace one member, re-zip, and re-open asserting structure + mimetype placement
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Implement `flamberge-formats::ocf` (I/O + XML only, no crypto). Reference: DEDRM_SCHEMES §4.4 (B&N) / §7.3 (ADEPT); Python `ineptepub.py`/`ignobleepub.py`.

1. `OcfEncryption::parse(zip)`: open zip; if `META-INF/rights.xml` present, extract the `{adept}encryptedKey` element text via a namespace-aware `quick_xml::NsReader` → `wrapped_key_b64`. If `META-INF/encryption.xml` present, collect every `{enc}CipherReference@URI` → `encrypted_paths` (HashSet).
2. `EpubScheme` enum {Adept, BarnesNoble}; `OcfEncryption::scheme()` maps wrapped-key length 172→Adept, 64→BarnesNoble, else None. Constants `ADEPT_KEY_LEN=172`, `BN_KEY_LEN=64`.
3. `is_encrypted_epub(zip)`: true iff BOTH rights.xml and encryption.xml members exist (matches Python detection guard).
4. `read_all_members(zip)`: decompress every member in archive order → Vec<(name, bytes)> so the scheme can decrypt listed members.
5. `repackage(original, replacements)`: emit new zip — `mimetype` first + STORED, all other members DEFLATED, preserve last-modified time + unix permissions, DROP rights.xml/encryption.xml, substitute replacement bytes for named members, re-deflate unchanged members' plaintext.

Tests (colocated): synthetic EPUB builder; parse extracts key+paths; scheme detection 172/64/absent; is_encrypted_epub true/false; round-trip repackage replacing one member asserts mimetype first+STORED, rights/encryption dropped, structure preserved.

Verify: cargo fmt/build/clippy -D warnings/test. Update CLAUDE.md Status.
<!-- SECTION:PLAN:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Implemented `flamberge-formats::ocf`, the shared EPUB/OCF container layer for the ADEPT (§7.3) and B&N (§4.4) schemes — I/O + XML only, no crypto.

**API**
- `OcfEncryption::parse(zip)` — namespace-aware `quick_xml::NsReader` extracts the `{adept}encryptedKey` text from `rights.xml` (verbatim, so its length stays a discriminator) and every `{enc}CipherReference@URI` from `encryption.xml` into a `HashSet`.
- `EpubScheme` + `OcfEncryption::scheme()` — maps wrapped-key length 172→Adept, 64→BarnesNoble, else None (constants `ADEPT_KEY_LEN`/`BN_KEY_LEN`).
- `is_encrypted_epub(zip)` — true iff both META-INF DRM files are present (matches the reference plugins' presence guard); false = DRM-free / not this scheme.
- `read_all_members(zip)` — decompresses every member in order so the scheme layer can obtain ciphertext.
- `repackage(original, replacements)` — `mimetype` first + STORED, all other members DEFLATED, preserves last-modified time + unix permissions, drops `rights.xml`/`encryption.xml`, substitutes decrypted replacement bytes.

**Tests (10, colocated):** parse extracts key+paths; ADEPT/B&N/unknown-length scheme detection; plain EPUB reports not-encrypted; encrypted EPUB detected; `read_all_members` order+content; round-trip repackage asserting mimetype-first+STORED, others DEFLATED, META files dropped, replacement applied, and timestamp/permission preservation.

**Verification:** `cargo fmt --check`, `cargo clippy --workspace --all-targets -D warnings`, and `cargo test --workspace` all green (formats crate 33→43 tests). No panic/unwrap/expect outside tests; all public items documented and cite the spec §.

This is the first consumer of the `quick-xml` workspace dependency. Next: the ADEPT (TASK-9) and B&N (TASK-10) EPUB schemes build the crypto on top of this layer. CLAUDE.md Status updated.
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
