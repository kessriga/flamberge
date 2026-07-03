---
id: TASK-5
title: Implement Topaz DRM decryption (dkey → book key → records)
status: To Do
assignee: []
created_date: '2026-07-03 19:56'
labels:
  - schemes
  - kindle
  - topaz
milestone: m-1
dependencies:
  - TASK-4
references:
  - docs/DEDRM_SCHEMES.md
  - ../../external/DeDRM_tools/DeDRM_plugin/topazextract.py
modified_files:
  - crates/flamberge-schemes/src/topaz.rs
priority: medium
ordinal: 5000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement flamberge-schemes::topaz using the container parser (task-4) and the existing Topaz cipher (flamberge-crypto::topaz). Read the dkey record (unencrypted, zlib-inflate if compressed). For each candidate PID (8 bytes), Topaz-decrypt each dkey sub-record and validate the 24-byte `PID`..`pid` structure with matching embedded PID; the first valid sub-record yields the 8-byte book key. Then Topaz-decrypt every payload record flagged encrypted (negative index) and zlib-inflate compressed records, extracting the named files. Books with no dkey are treated as unencrypted.

Output: for a first cut, emit the extracted record set (or a repackaged container). Reconstructing readable HTML/SVG (genbook/flatxml2html) is out of scope for this task and should be tracked separately if desired. Spec: docs/DEDRM_SCHEMES.md §5.3–5.4. Original: topazextract.py (processBook, decryptDkeyRecords, decryptRecord).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 dkey sub-records are Topaz-decrypted per candidate PID and validated against the PID/pid magic + embedded-PID self-check; first valid match yields the 8-byte book key
- [ ] #2 Encrypted payload records (negative index) are Topaz-decrypted and compressed records zlib-inflated
- [ ] #3 A book with no dkey is handled as unencrypted
- [ ] #4 Wrong PIDs are rejected via the structural self-check and the next candidate is tried
- [ ] #5 Unit test: construct a synthetic dkey + encrypted record, decrypt with the correct PID, and assert recovered content; document that full HTML/SVG rendering is out of scope
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
