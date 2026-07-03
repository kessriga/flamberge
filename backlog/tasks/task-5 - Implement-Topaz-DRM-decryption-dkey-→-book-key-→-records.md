---
id: TASK-5
title: Implement Topaz DRM decryption (dkey → book key → records)
status: Done
assignee:
  - kessriga
created_date: '2026-07-03 19:56'
updated_date: '2026-07-03 23:17'
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
- [x] #1 dkey sub-records are Topaz-decrypted per candidate PID and validated against the PID/pid magic + embedded-PID self-check; first valid match yields the 8-byte book key
- [x] #2 Encrypted payload records (negative index) are Topaz-decrypted and compressed records zlib-inflated
- [x] #3 A book with no dkey is handled as unencrypted
- [x] #4 Wrong PIDs are rejected via the structural self-check and the next candidate is tried
- [x] #5 Unit test: construct a synthetic dkey + encrypted record, decrypt with the correct PID, and assert recovered content; document that full HTML/SVG rendering is out of scope
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Implement `flamberge-schemes::topaz` on the merged TASK-4 container + `flamberge-crypto::topaz::TopazCipher`. Spec §5.3–5.4; original `topazextract.py` (processBook, decryptDkeyRecords, getBookPayloadRecord). Add `flate2` to schemes deps for zlib inflate.

**dkey → book key (§5.4):** if no `dkey` header record ⇒ unencrypted (book_key = None). Else read `dkey[0]` payload (unencrypted; inflate if compressed). Blob = `[nbKeyRecords:1][len:1][subRecord:len]…`. Candidate 8-byte PIDs from `keys.pids` + serial-derived (`pid::book_pid_from_serial` with metadata `(md1,md2)`, `pid::eink_pid_from_serial`), each truncated to `pid[0:8]`. For each PID, Topaz-decrypt each 24-byte sub-record and validate struct `3sB8sB8s3s`: magic `PID`, len==8, embedded pid == candidate, len==8, magic `pid`; first valid ⇒ 8-byte book key (bytes 13..21). None match ⇒ `NoKeyWorked`.

**Records (§5.2):** repackage into a decrypted **TPZ0** container (extension `tpz`). Skip `dkey` (key store). `metadata` re-serialized specially (no index field: tag + flags=0 + count + lp pairs). All other records via `payload_record`: Topaz-decrypt if `encrypted` (book key), zlib-inflate if `compressed`, re-emit uncompressed with positive index; rebuild header with new relative offsets. Title from metadata `Title`.

**Helpers:** `encode_number`/`encode_lp` (inverse of `read_encoded_number`, incl. 0x7F leading-0xFF disambiguation), `zlib_inflate` (flate2 ZlibDecoder), `validate_dkey`, `find_book_key`, `candidate_pids`, `repackage`.

**Tests (colocated):** synthetic container builder with a `dkey` (1 sub-record encrypted under the correct PID) + one encrypted-uncompressed page + one encrypted-compressed page + metadata(Title). Assert: correct PID recovers book key and page contents (round-trip through our parser); compressed page inflated; wrong-only PID ⇒ NoKeyWorked; correct PID among wrong ones works; no-dkey container ⇒ passthrough/unencrypted; title extracted. Document HTML/SVG rendering out of scope.

Verify: cargo fmt / build / test / clippy -D warnings.
<!-- SECTION:PLAN:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Implemented `flamberge-schemes::topaz` end-to-end on the TASK-4 container parser and `flamberge-crypto::topaz::TopazCipher`.

**Key recovery (§5.4):** `read_dkey_blob` reads `dkey[0]` (inflating if compressed); absence of a `dkey` header record means the book is unencrypted (`book_key = None`). `candidate_pids` builds 8-byte PIDs from `keys.pids` plus serial-derived PIDs (`pid::book_pid_from_serial`/`eink_pid_from_serial`, metadata `(md1,md2)`), truncated to `pid[0:8]`. `find_book_key` Topaz-decrypts each 24-byte sub-record per candidate; `validate_dkey` enforces the `PID`/`pid` magic, both length bytes == 8, and the embedded-PID self-check, returning bytes 13..21 as the book key. No candidate matching ⇒ `NoKeyWorked`.

**Records (§5.2):** `repackage` rebuilds a decrypted `TPZ0` (extension `tpz`): each payload record is Topaz-decrypted (if the stored index was negative) then zlib-inflated (if compressed) and re-emitted uncompressed with a positive index and recomputed offsets. The `dkey` key store is dropped; `metadata` is re-serialized (it has no index field). Title taken from metadata `Title`.

**Deps:** added `flate2` to flamberge-schemes for zlib inflate.

**Tests (6, colocated):** synthetic TPZ0 fixtures — correct PID recovers the book key and both an uncompressed and a compressed+encrypted page (round-tripped through our own parser); correct PID selected among wrong ones; wrong-only PID ⇒ NoKeyWorked; no-dkey container decrypts as unencrypted with title; non-Topaz input ⇒ NotThisScheme; encode/decode number round-trip. HTML/SVG rendering (§5.5–5.6) documented out of scope.

Verified: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` all clean (schemes 13→19 tests). No `unwrap`/`panic` on non-test paths.

Files: crates/flamberge-schemes/src/topaz.rs, crates/flamberge-schemes/Cargo.toml, CLAUDE.md.
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
