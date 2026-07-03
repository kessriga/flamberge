---
id: TASK-4
title: Implement the Topaz TPZ0 container parser
status: To Do
assignee: []
created_date: '2026-07-03 19:55'
labels:
  - formats
  - kindle
  - topaz
milestone: m-1
dependencies: []
references:
  - docs/DEDRM_SCHEMES.md
  - ../../external/DeDRM_tools/DeDRM_plugin/topazextract.py
modified_files:
  - crates/dedrm-formats/src/topaz_container.rs
priority: medium
ordinal: 4000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement dedrm-formats::topaz_container fully. Parse the TPZ0 header: variable-length encoded numbers (§5.1, incl. the leading-0xFF negative marker), the named header records (0x63 marker, length-prefixed name, [offset, decompressed_len, compressed_len] triples), the 0x64 end marker, and resolve book_payload_offset. Provide payload-record access that reads a record at book_payload_offset+offset, decodes its tag + encoded index (negative => encrypted flag), and returns the raw bytes plus encrypted/compressed flags. Parse the inline metadata record (1-byte flags + 1-byte count + key/value length-prefixed strings), exposing the `keys` list and its referenced values for PID metadata.

This is the data layer; decryption (Topaz cipher) and zlib inflate happen in the scheme task, but expose a helper that returns whether a record is compressed (compressed_len>0). Spec: docs/DEDRM_SCHEMES.md §5.1–5.2. Original: topazextract.py (parseTopazHeaders, getBookPayloadRecord, parseMetadata).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 read_encoded_number decodes single-byte, multi-byte, and negative (leading 0xFF) values with correct byte counts
- [ ] #2 Header parsing yields a name->[RecordEntry] map and the correct book_payload_offset; rejects a bad magic/marker with a typed error
- [ ] #3 Payload-record access returns tag, index, encrypted flag (negative index), compressed flag, and raw bytes
- [ ] #4 Metadata record parsing exposes the `keys` list and the values it references (md1/md2 for PID generation)
- [ ] #5 Unit tests cover encoded-number edge cases and a synthetic container with one compressed and one encrypted record
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
