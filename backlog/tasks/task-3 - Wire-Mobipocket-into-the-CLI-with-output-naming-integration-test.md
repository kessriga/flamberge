---
id: TASK-3
title: Wire Mobipocket into the CLI with output naming + integration test
status: Done
assignee:
  - Kessriga Jeükal
created_date: '2026-07-03 19:55'
updated_date: '2026-07-03 20:48'
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
  - crates/flamberge-formats/src/mobi.rs
  - crates/flamberge-schemes/src/lib.rs
  - crates/flamberge-schemes/src/mobipocket.rs
  - crates/flamberge-cli/src/main.rs
  - crates/flamberge-cli/tests/mobipocket_cli.rs
priority: high
ordinal: 3000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Complete the end-to-end Mobipocket experience through the `flamberge` binary and lock it with an integration test. The scheme dispatcher already routes Kindle extensions and magic bytes; make `flamberge decrypt book.azw --serial <sn>` (or `--pid`) produce a correct DRM-free file.

Add output-extension logic (.mobi, .azw3 for KF8 mobi_version>=8, .azw4 for Print Replica) and title-based output naming per k4mobidedrm.py. Add a workspace-level integration test (tests/) that decrypts a small committed Mobipocket fixture with a known PID/serial and asserts the plaintext. If no redistributable DRMed fixture is available, synthesize one by PC1-encrypting known content with a constructed voucher, and document that in the test.

Spec: docs/DEDRM_SCHEMES.md §2.6. Original: k4mobidedrm.py (GetDecryptedBook, decryptBook naming).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 `flamberge decrypt <mobi/azw>` with a valid --pid or --serial writes a DRM-free file with the correct extension (.mobi/.azw3/.azw4)
- [x] #2 Output filename defaults follow the plugin's title-based naming when the source name is an Amazon ASIN/UUID pattern
- [x] #3 A committed or synthesized Mobipocket fixture is decrypted by an integration test that asserts the plaintext content
- [x] #4 A wrong PID/serial fails with a clear 'no key worked' message and non-zero exit, without writing a partial file
- [x] #5 Fixture provenance and any synthesis steps are documented in the test file
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Mobipocket engine (TASK-2) is done and the CLI already routes `decrypt --pid/--serial` through `flamberge_schemes::decrypt` and writes `<stem>_nodrm.<ext>` with the scheme-chosen extension (.mobi/.azw3/.azw4). Remaining gaps for the acceptance criteria are title-based output naming and an end-to-end integration test.

Steps (TDD — test first each step):
1. flamberge-formats::mobi — add `MobiHeader::book_title(&self, record0, db_name) -> String` mirroring mobidedrm.py `getBookTitle`: EXTH 503, else MOBI full-name offset (>II at 0x54), else PalmDB name (first NUL-terminated 32 bytes). Codec: 65001→utf-8 (lossy), else latin-1 approx (windows-1252 high bytes are dropped by cleanup_name anyway). Unit test.
2. flamberge-schemes — add `title: Option<String>` to `DecryptedBook`; mobipocket::decrypt computes it once and sets it at both return sites.
3. flamberge-cli — add `cleanup_name` (port of k4mobidedrm.cleanup_name: char subs, whitespace collapse, strip <32/>126, strip leading/trailing dots, empty→"DecryptedBook") and ASIN/UUID detection (`^B[A-Z0-9]{9}(_EBOK|_EBSP|_sample)?$`, plus a well-formed UUID `[0-9A-Fa-f-]{36}` — noting the plugin's UUID regex is malformed). `default_output` becomes: if stem matches ASIN/UUID → `<stem>_<clean_title>_nodrm.<ext>`, else `<stem>_nodrm.<ext>`; cap length like the plugin (>150 → first99+"--"+last49). Unit tests. No regex crate — hand-rolled matchers.
4. Integration test `crates/flamberge-cli/tests/mobipocket_cli.rs` driving the compiled `flamberge` binary (CARGO_BIN_EXE_flamberge). Synthesize a type-2 Mobipocket .azw fixture at test time (PC1-encrypt known plaintext under a finalkey, wrap in a voucher keyed to a known PID via KEYVEC1; ASIN-style filename + EXTH 503 title) — provenance documented in the file. Assert: success exit, output named with cleaned title, decrypted text record == plaintext (AC#1,#2,#3,#5); wrong-pid → non-zero exit, stderr says no key worked, no partial output file (AC#4). Add dev-deps flamberge-crypto/flamberge-schemes (KEYVEC1, pc1) to flamberge-cli.
5. Verify build/test/clippy clean, no unwrap on non-test paths, doc comments on public items.

Note: proceeding autonomously per the user's delegation ("implement TASK-3"); plan recorded here per the backlog workflow rather than blocking on interactive approval.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
The integration test surfaced a real dispatch bug: on a wrong PID, mobipocket::decrypt returns NoKeyWorked, but the old loop stored it in last_err and continued to the KFX stub, whose Unimplemented error masked it (AC#4 would have failed with 'not yet implemented: kfx::decrypt'). Fixed decrypt() to return immediately on any non-NotThisScheme error, matching the documented NotThisScheme='fall through, everything else is terminal' contract.

No redistributable DRMed fixture exists, so the integration test synthesizes a structurally faithful type-2 BOOKMOBI at run time (PC1-wrapped voucher keyed to a known PID + EXTH 503 title) and drives the compiled `flamberge` binary via CARGO_BIN_EXE_flamberge. Provenance is documented in the test module doc-comment.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Wired the already-complete Mobipocket engine into an end-to-end CLI experience and locked it with an integration test.

Changes:
- flamberge-formats: `MobiHeader::book_title` recovers the display title (EXTH 503 → MOBI full-name offset at 0x54 → PalmDB name), with UTF-8/Latin-1 codec handling (§2.6, mobidedrm.py getBookTitle).
- flamberge-schemes: `DecryptedBook` gained a `title: Option<String>` field, populated by mobipocket::decrypt. Fixed the scheme dispatcher so a claiming scheme's error is returned rather than masked by a later candidate's error (required for a clear 'no key worked' failure).
- flamberge-cli: title-based output naming — when the source stem is an opaque Amazon download name (ASIN `^B[A-Z0-9]{9}(_EBOK|_EBSP|_sample)?$` or 36-char UUID) the cleaned title is appended (`<stem>_<title>_nodrm.<ext>`); otherwise the stem is kept. Ported `cleanup_name` byte-for-byte and the >150-char shortening from k4mobidedrm.decryptBook.
- Integration test `crates/flamberge-cli/tests/mobipocket_cli.rs` drives the compiled binary against a synthesized type-2 fixture: asserts the correct extension, title-based filename, and recovered plaintext; and that a wrong PID exits non-zero with a clear message and writes no partial file.

Verification: cargo build/test/clippy all clean; 36 tests pass (unit + 2 integration); no unwrap/expect/panic on production paths.
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
