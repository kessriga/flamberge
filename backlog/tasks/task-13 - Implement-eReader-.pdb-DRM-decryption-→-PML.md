---
id: TASK-13
title: Implement eReader (.pdb) DRM decryption → PML
status: To Do
assignee: []
created_date: '2026-07-03 19:59'
labels:
  - schemes
  - ereader
milestone: m-3
dependencies: []
references:
  - docs/DEDRM_SCHEMES.md
  - ../../external/DeDRM_tools/DeDRM_plugin/erdr2pml.py
modified_files:
  - crates/flamberge-schemes/src/ereader.rs
priority: low
ordinal: 13000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement flamberge-schemes::ereader using the PalmDB parser (flamberge-formats::palmdb) and the DES helpers already in flamberge-crypto (ecb_decrypt, fix_key), plus the user-key generator in flamberge-keys::ereader.

Flow (§8): validate record-0 version (259/260/272); parse record 1 (DES key = first 8 bytes via fix_key), decrypt last 8 bytes to get cookie_shuf/cookie_size (range-checked), decrypt the last cookie_size bytes, and unshuffle. Read the version-dependent encrypted-key + SHA-1 offsets from the header, recover content_key = DES(fix_key(user_key), encrypted_key), and validate SHA1(content_key)==stored digest. Decrypt text records (records 1..num_text_pages) via zlib(DES(fix_key(content_key), record)); handle footnotes/sidebars (v272) with the XOR table. Emit PML (+ images) as a .pmlz (ZIP_STORED), with cp1252 high-byte escaping. Original: erdr2pml.py.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Record-0 version gate (259/260/272) and record-1 cookie decrypt + unshuffle produce a valid header with in-range cookie_shuf/cookie_size
- [ ] #2 content_key = DES(fix_key(user_key), encrypted_key) is validated against the stored SHA-1; wrong name/CC is rejected clearly
- [ ] #3 Text records decrypt via zlib(DES(fix_key(content_key), record)); v272 footnotes/sidebars handled via the XOR table
- [ ] #4 Output is a .pmlz (stored) with images extracted and cp1252 high bytes escaped to \a###
- [ ] #5 Integration test decrypts a synthesized eReader .pdb using a key from flamberge-keys::ereader and asserts PML content
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
