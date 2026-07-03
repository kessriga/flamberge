---
id: TASK-10
title: Implement Barnes & Noble EPUB decryption
status: To Do
assignee: []
created_date: '2026-07-03 19:57'
labels:
  - schemes
  - epub
  - ignoble
milestone: m-2
dependencies:
  - TASK-8
references:
  - docs/DEDRM_SCHEMES.md
  - ../../external/DeDRM_tools/DeDRM_plugin/ignobleepub.py
modified_files:
  - crates/flamberge-schemes/src/ignoble.rs
priority: medium
ordinal: 10000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement flamberge-schemes::ignoble::decrypt_epub on the OCF layer (task-8), using the existing B&N keygen (flamberge-keys::ignoble).

Flow (§4.4): user key = base64-decode the 28-char ccHash, take first 16 bytes. AES-128-CBC decrypt the 64-char (48-byte) wrapped key from rights.xml with a zero IV, strip PKCS#7, take the last 16 bytes as the book key. For each encrypted file: AES-128-CBC decrypt with the book key (zero IV), drop the first 16 bytes, strip PKCS#7, raw-inflate (windowBits -15). Repackage via the OCF writer. Original: ignobleepub.py.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 User key first-16-bytes unwraps the rights.xml key via AES-128-CBC (zero IV) + PKCS#7 strip, taking the last 16 bytes as book key
- [ ] #2 Encrypted files decrypt with the book key (zero IV), drop first 16 bytes, PKCS#7 strip, then raw inflate
- [ ] #3 Output repackaged via the OCF writer; non-B&N EPUBs reported as not-this-scheme
- [ ] #4 Integration test decrypts a synthesized B&N EPUB using a key from flamberge-keys::ignoble and asserts content
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
