---
id: TASK-4
title: Implement the Topaz TPZ0 container parser
status: Done
assignee:
  - Kessriga Jeükal
created_date: '2026-07-03 19:55'
updated_date: '2026-07-03 22:21'
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
  - crates/flamberge-formats/src/topaz_container.rs
priority: medium
ordinal: 4000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement flamberge-formats::topaz_container fully. Parse the TPZ0 header: variable-length encoded numbers (§5.1, incl. the leading-0xFF negative marker), the named header records (0x63 marker, length-prefixed name, [offset, decompressed_len, compressed_len] triples), the 0x64 end marker, and resolve book_payload_offset. Provide payload-record access that reads a record at book_payload_offset+offset, decodes its tag + encoded index (negative => encrypted flag), and returns the raw bytes plus encrypted/compressed flags. Parse the inline metadata record (1-byte flags + 1-byte count + key/value length-prefixed strings), exposing the `keys` list and its referenced values for PID metadata.

This is the data layer; decryption (Topaz cipher) and zlib inflate happen in the scheme task, but expose a helper that returns whether a record is compressed (compressed_len>0). Spec: docs/DEDRM_SCHEMES.md §5.1–5.2. Original: topazextract.py (parseTopazHeaders, getBookPayloadRecord, parseMetadata).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 read_encoded_number decodes single-byte, multi-byte, and negative (leading 0xFF) values with correct byte counts
- [x] #2 Header parsing yields a name->[RecordEntry] map and the correct book_payload_offset; rejects a bad magic/marker with a typed error
- [x] #3 Payload-record access returns tag, index, encrypted flag (negative index), compressed flag, and raw bytes
- [x] #4 Metadata record parsing exposes the `keys` list and the values it references (md1/md2 for PID generation)
- [x] #5 Unit tests cover encoded-number edge cases and a synthetic container with one compressed and one encrypted record
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Port `topazextract.py` (parseTopazHeaders, getBookPayloadRecord, parseMetadata) into `flamberge-formats::topaz_container`, spec §5.1–5.2. Data layer only — no decrypt/inflate.

1. `read_encoded_number(&[u8]) -> Result<(i64, usize)>`: base-128 BE varint; leading 0xFF = negative-sign marker; single byte <0x80 direct; else accumulate `(acc<<7)+(b&0x7F)` while high bit set. Returns value + bytes consumed.
2. Private `Reader` cursor over `&[u8]` (u8 / encoded / lp_string / bytes / seek) with Truncated errors — no panics/slicing.
3. `TopazContainer::parse`: verify `TPZ0` magic (else BadMagic); read nbRecords; per record `0x63` marker + lp-name + nbValues triples `[offset, decompLen, compLen]` into `HashMap<Vec<u8>, Vec<RecordEntry>>`; require `0x64` end marker; `book_payload_offset` = cursor pos. Typed error on bad marker.
4. `RecordEntry::is_compressed()` = `compressed_len > 0`.
5. `payload_record(data, name, index) -> Result<PayloadRecord>`: seek `book_payload_offset+offset`, read lp-tag (must match name), encoded index (negative => encrypted, real = `-idx-1`, validate == index); raw = compLen bytes if compressed else decompLen bytes (still encoded — decrypt/inflate deferred to scheme). Fields: tag, index, encrypted, compressed, raw slice.
6. `parse_metadata(data) -> Result<Metadata>`: seek metadata[0], lp-tag == "metadata", 1-byte flags + 1-byte count, count×[key lp-string, value lp-string] into BTreeMap. `keys()` splits the `keys` value on commas; `pid_meta() -> (md1, md2)` where md1=`keys` value, md2=concat of referenced values (mirrors getPIDMetaInfo).
7. Tests: encoded-number edge cases (single/multi/negative/zero/truncated); synthetic TPZ0 container with a metadata record + one compressed + one encrypted `page` record; bad-magic rejection.

Verify: cargo fmt / build / test / clippy -D warnings.
<!-- SECTION:PLAN:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Implemented `flamberge-formats::topaz_container` — the Topaz TPZ0 data layer (spec §5.1–5.2, ported from `topazextract.py`). No decryption/inflate here; those stay in `flamberge-schemes` (TASK-5).

**Public API**
- `read_encoded_number(&[u8]) -> Result<(i64, usize)>` — base-128 big-endian varint with the leading-`0xFF` negative-sign marker; returns value + bytes consumed.
- `TopazContainer::parse(&[u8])` — validates `TPZ0` magic, walks the `0x63`-marked named header records (lp-name + N `[offset, decompressed_len, compressed_len]` triples), requires the `0x64` end marker, and records `book_payload_offset`.
- `RecordEntry::is_compressed()` — `compressed_len > 0`.
- `TopazContainer::payload_record(data, name, index) -> PayloadRecord` — seeks `book_payload_offset + offset`, validates the record tag and decoded index (negative stored index ⇒ `encrypted`, real index `-stored-1`), and returns the still-encoded/compressed raw bytes plus `encrypted`/`compressed` flags.
- `TopazContainer::parse_metadata(data) -> Metadata` — inline `metadata` record (flags + count + key/value lp-string pairs); `Metadata::keys()` splits the `keys` value, `Metadata::pid_meta()` returns `(md1, md2)` for PID generation (mirrors `getPIDMetaInfo`).

**Robustness:** all reads go through a bounds-checked `Reader` cursor returning `FormatError::Truncated`; bad magic ⇒ `BadMagic`, bad markers/mismatched tag/index/negative lengths ⇒ `Invalid`. No `panic!`/`unwrap`/`expect` on non-test paths.

**Tests (11 new, 20 total in the crate):** encoded-number single/multi-byte/negative/zero/round-trip/truncated edge cases; a synthetic TPZ0 container with a metadata record + one compressed (`page[0]`) and one encrypted (`page[1]`) record exercising `parse`/`payload_record`/`parse_metadata`; bad-magic and bad-header-marker rejection; missing-record typed error.

Notably surfaced a genuine varint ambiguity: a positive number whose top 7-bit group is `0x7F` would lead with `0x7F|0x80 = 0xFF` and collide with the sign marker — the canonical container form (and the test encoder) prepends a zero continuation group; the decoder round-trips it.

**Verification:** `cargo fmt --all --check`, `cargo build --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` all pass. Committed on `feat/task-4-topaz-container` as `feat(formats): implement Topaz TPZ0 container parser (TASK-4)`.
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
