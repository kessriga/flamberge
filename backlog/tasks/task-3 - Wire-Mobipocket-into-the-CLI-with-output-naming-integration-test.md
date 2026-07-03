---
id: TASK-3
title: Wire Mobipocket into the CLI with output naming + integration test
status: To Do
assignee: []
created_date: '2026-07-03 19:55'
labels:
  - cli
  - kindle
  - mobipocket
  - testing
milestone: m-0
dependencies:
  - TASK-2
references:
  - docs/DEDRM_SCHEMES.md
  - ../../external/DeDRM_tools/DeDRM_plugin/k4mobidedrm.py
modified_files:
  - crates/dedrm-cli/src/main.rs
  - crates/dedrm-schemes/src/lib.rs
  - tests/
priority: high
ordinal: 3000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Complete the end-to-end Mobipocket experience through the `dedrm` binary and lock it with an integration test. The scheme dispatcher already routes Kindle extensions and magic bytes; make `dedrm decrypt book.azw --serial <sn>` (or `--pid`) produce a correct DRM-free file.

Add output-extension logic (.mobi, .azw3 for KF8 mobi_version>=8, .azw4 for Print Replica) and title-based output naming per k4mobidedrm.py. Add a workspace-level integration test (tests/) that decrypts a small committed Mobipocket fixture with a known PID/serial and asserts the plaintext. If no redistributable DRMed fixture is available, synthesize one by PC1-encrypting known content with a constructed voucher, and document that in the test.

Spec: docs/DEDRM_SCHEMES.md §2.6. Original: k4mobidedrm.py (GetDecryptedBook, decryptBook naming).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `dedrm decrypt <mobi/azw>` with a valid --pid or --serial writes a DRM-free file with the correct extension (.mobi/.azw3/.azw4)
- [ ] #2 Output filename defaults follow the plugin's title-based naming when the source name is an Amazon ASIN/UUID pattern
- [ ] #3 A committed or synthesized Mobipocket fixture is decrypted by an integration test that asserts the plaintext content
- [ ] #4 A wrong PID/serial fails with a clear 'no key worked' message and non-zero exit, without writing a partial file
- [ ] #5 Fixture provenance and any synthesis steps are documented in the test file
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
