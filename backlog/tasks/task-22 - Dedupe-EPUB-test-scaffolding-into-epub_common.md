---
id: TASK-22
title: Dedupe EPUB test scaffolding into epub_common
status: Done
assignee: []
created_date: '2026-07-04 09:59'
updated_date: '2026-07-04 22:56'
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
- [x] #1 The EPUB test-fixture builders (pkcs7_pad, raw_deflate, encrypt_member, rights_xml, encryption_xml, build_zip, read_zip) have a single shared definition rather than being duplicated across adept.rs and ignoble.rs
- [x] #2 Both the ADEPT and B&N scheme test modules use the shared helpers; no verbatim copy remains
- [x] #3 All existing flamberge-schemes tests still pass with the shared helpers; cargo build/test/clippy/fmt are clean
- [x] #4 No production (non-test) behaviour changes
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Add a `#[cfg(test)] pub(crate) mod test_support` to `epub_common.rs` holding the shared fixture builders (`pkcs7_pad`, `raw_deflate`, `encrypt_member`, `rights_xml`, `encryption_xml`, `build_zip`, `read_zip`) plus the `ADEPT_NS`/`ENC_NS` constants they need. Items are `pub(crate)` so both scheme test modules can import them; each has a doc comment.
2. In `adept.rs` tests: delete the moved helpers/consts, add `use crate::epub_common::test_support::*;`, and drop now-unused imports (`std::io::{Read, Write}`, `flamberge_crypto::aes`, `zip::*`). Keep scheme-specific helpers (`seeded_rng`, `rsa_wrap`, `pkcs1_block`, `synth_adept_epub`).
3. In `ignoble.rs` tests: same — delete moved helpers/consts, glob-import test_support, drop unused imports. Keep `B64`, `user_key_from_cchash`, `wrap_book_key`, `synth_bn_epub`.
4. Verify `cargo build`, `cargo test -p flamberge-schemes`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all -- --check` are all clean. No production behaviour change.
<!-- SECTION:PLAN:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Deduplicated the EPUB test-fixture scaffolding that was copy-pasted verbatim between `adept.rs` and `ignoble.rs`.

**What moved:** the scheme-agnostic builders `pkcs7_pad`, `raw_deflate`, `encrypt_member`, `rights_xml`, `encryption_xml`, `build_zip`, `read_zip` (plus the `ADEPT_NS`/`ENC_NS` constants) now have a single definition in a new `#[cfg(test)] pub(crate) mod test_support` inside `crates/flamberge-schemes/src/epub_common.rs`. Both scheme test modules glob-import it (`use crate::epub_common::test_support::*;`).

**What stayed:** each scheme keeps its own key-wrapping + book synthesis — ADEPT's `rsa_wrap`/`pkcs1_block`/`seeded_rng`/`synth_adept_epub`, B&N's `user_key_from_cchash`/`wrap_book_key`/`B64`/`synth_bn_epub` — and all actual test cases.

`test_support` lives in `epub_common` (rather than a `tests/` support crate) so it can sit alongside the production `decrypt_member` the fixtures mirror, and because a crate-external test crate cannot reach crate-private items.

Test-only; no production behaviour changed. Verified clean: `cargo build`, `cargo test -p flamberge-schemes`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all -- --check`. Merged via PR #22.
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
