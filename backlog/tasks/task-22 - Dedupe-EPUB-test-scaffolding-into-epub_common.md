---
id: TASK-22
title: Dedupe EPUB test scaffolding into epub_common
status: To Do
assignee: []
created_date: '2026-07-04 09:59'
labels:
  - schemes
  - epub
  - cleanup
  - tests
dependencies: []
ordinal: 22000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up from the TASK-11 code review (PR #12), covering pre-existing code that was outside that PR's diff. The EPUB-packaging test helpers — `pkcs7_pad`, `raw_deflate`, `encrypt_member`, `rights_xml`, `encryption_xml`, `build_zip`, `read_zip` — are copy-pasted verbatim (~120 lines) between the test modules of `crates/flamberge-schemes/src/adept.rs` (~L109-254) and `crates/flamberge-schemes/src/ignoble.rs` (~L119-252). The `epub_common` refactor (TASK-10) hoisted the production `decrypt_member`/`decode_b64` path but left this test scaffolding duplicated.

Because both schemes now depend on the same shared `epub_common::decrypt_member`, the duplicated builders can silently diverge: a change to how a member's IV is prepended, or how `build_zip` stores the `mimetype` entry, must be edited in both files, and updating only one makes the two schemes' tests stop exercising the same path.

Extract the shared builders into one place — e.g. a `#[cfg(test)]` helper module in `epub_common` (or a small test-support module) that both scheme test modules import — so there is a single definition. Keep each scheme's actual test cases where they are; only the reusable fixture builders move.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The EPUB test-fixture builders (pkcs7_pad, raw_deflate, encrypt_member, rights_xml, encryption_xml, build_zip, read_zip) have a single shared definition rather than being duplicated across adept.rs and ignoble.rs
- [ ] #2 Both the ADEPT and B&N scheme test modules use the shared helpers; no verbatim copy remains
- [ ] #3 All existing flamberge-schemes tests still pass with the shared helpers; cargo build/test/clippy/fmt are clean
- [ ] #4 No production (non-test) behaviour changes
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
