---
id: TASK-8
title: Implement OCF/EPUB reader + writer
status: To Do
assignee: []
created_date: '2026-07-03 19:57'
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
  - crates/dedrm-formats/src/ocf.rs
priority: medium
ordinal: 8000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement dedrm-formats::ocf, the shared EPUB layer for both Adobe ADEPT and B&N ignoble. Read `META-INF/rights.xml` (extract the base64 `adept:encryptedKey` text) and `META-INF/encryption.xml` (collect the set of encrypted file paths from `enc:CipherReference@URI`). Provide a detector for ADEPT vs B&N (both present these files; disambiguate by the wrapped-key length: 172 chars = ADEPT/1024-bit RSA, 64 chars = B&N). Provide a repackaging writer that emits a new zip with `mimetype` stored first (ZIP_STORED) and the rest deflated, preserving entry metadata, dropping rights.xml/encryption.xml, and replacing decrypted members.

This is I/O + XML only; the crypto lives in the scheme tasks. Spec: docs/DEDRM_SCHEMES.md §4.4 / §7.3. Original: ineptepub.py, ignobleepub.py.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Parses rights.xml/encryption.xml and exposes the wrapped-key base64 and the encrypted-path set
- [ ] #2 Detects ADEPT vs B&N by wrapped-key length (172 vs 64) and reports 'not encrypted' when the META-INF files are absent
- [ ] #3 Repackaging writer emits mimetype first + stored, deflates other members, preserves entry metadata, and omits rights.xml/encryption.xml
- [ ] #4 Round-trip test: read a synthetic encrypted EPUB, replace one member, re-zip, and re-open asserting structure + mimetype placement
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
