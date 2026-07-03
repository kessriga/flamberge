---
id: TASK-5
title: Implement Topaz DRM decryption (dkey → book key → records)
status: In Progress
assignee:
  - kessriga
created_date: '2026-07-03 19:56'
updated_date: '2026-07-03 23:12'
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

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Implement `flamberge-schemes::topaz` on the merged TASK-4 container + `flamberge-crypto::topaz::TopazCipher`. Spec §5.3–5.4; original `topazextract.py` (processBook, decryptDkeyRecords, getBookPayloadRecord). Add `flate2` to schemes deps for zlib inflate.

**dkey → book key (§5.4):** if no `dkey` header record ⇒ unencrypted (book_key = None). Else read `dkey[0]` payload (unencrypted; inflate if compressed). Blob = `[nbKeyRecords:1][len:1][subRecord:len]…`. Candidate 8-byte PIDs from `keys.pids` + serial-derived (`pid::book_pid_from_serial` with metadata `(md1,md2)`, `pid::eink_pid_from_serial`), each truncated to `pid[0:8]`. For each PID, Topaz-decrypt each 24-byte sub-record and validate struct `3sB8sB8s3s`: magic `PID`, len==8, embedded pid == candidate, len==8, magic `pid`; first valid ⇒ 8-byte book key (bytes 13..21). None match ⇒ `NoKeyWorked`.

**Records (§5.2):** repackage into a decrypted **TPZ0** container (extension `tpz`). Skip `dkey` (key store). `metadata` re-serialized specially (no index field: tag + flags=0 + count + lp pairs). All other records via `payload_record`: Topaz-decrypt if `encrypted` (book key), zlib-inflate if `compressed`, re-emit uncompressed with positive index; rebuild header with new relative offsets. Title from metadata `Title`.

**Helpers:** `encode_number`/`encode_lp` (inverse of `read_encoded_number`, incl. 0x7F leading-0xFF disambiguation), `zlib_inflate` (flate2 ZlibDecoder), `validate_dkey`, `find_book_key`, `candidate_pids`, `repackage`.

**Tests (colocated):** synthetic container builder with a `dkey` (1 sub-record encrypted under the correct PID) + one encrypted-uncompressed page + one encrypted-compressed page + metadata(Title). Assert: correct PID recovers book key and page contents (round-trip through our parser); compressed page inflated; wrong-only PID ⇒ NoKeyWorked; correct PID among wrong ones works; no-dkey container ⇒ passthrough/unencrypted; title extracted. Document HTML/SVG rendering out of scope.

Verify: cargo fmt / build / test / clippy -D warnings.
<!-- SECTION:PLAN:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 cargo build succeeds with no warnings
- [ ] #2 cargo test passes (unit and integration)
- [ ] #3 cargo clippy passes with no warnings
- [ ] #4 no panic!/unwrap/expect on non-test code paths
- [ ] #5 behavior matches docs/DEDRM_SCHEMES.md and code cites the relevant section
- [ ] #6 public items have doc comments
<!-- DOD:END -->
