---
id: TASK-1
title: Parse MOBI/PalmDoc/EXTH headers
status: In Progress
assignee:
  - Claude
created_date: '2026-07-03 19:54'
updated_date: '2026-07-03 20:09'
labels:
  - formats
  - kindle
  - mobipocket
milestone: m-0
dependencies: []
references:
  - docs/DEDRM_SCHEMES.md
  - ../../external/DeDRM_tools/DeDRM_plugin/mobidedrm.py
modified_files:
  - crates/dedrm-formats/src/mobi.rs
  - crates/dedrm-formats/src/lib.rs
priority: high
ordinal: 1000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Add a MOBI header parser to dedrm-formats (new module `mobi`, building on the existing `palmdb` parser) that extracts everything the Mobipocket DRM logic needs from record 0. This is the data layer the Mobipocket decryptor consumes; no decryption happens here.

Fields to expose (all big-endian): PalmDoc compression (1/2/17480), text record count, encryption type (0/1/2), MOBI header length and version, EXTH flag, the DRM block at 0xA8 (drm_ptr/drm_count/drm_size/drm_flags), and extra_data_flags (only when mobi_length>=0xE4 and mobi_version>=5, with the low-bit-cleared rule for non-HUFF/CDIC). Parse EXTH records into a type->bytes map, including type 209 (PID metadata), 503 (title), 406 (rental expiry).

Spec: docs/DEDRM_SCHEMES.md §2.1–2.2. Original: DeDRM_plugin/mobidedrm.py (MobiBook.__init__, getPIDMetaInfo).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A `MobiHeader` (or equivalent) type exposes compression, text record count, encryption type, mobi_length, mobi_version, exth flag, DRM block (ptr/count/size/flags), and extra_data_flags
- [ ] #2 EXTH records are parsed into a type->bytes map; rec209 and its referenced token bytes are reconstructed per getPIDMetaInfo
- [ ] #3 extra_data_flags low bit is cleared unless compression==17480 (HUFF/CDIC)
- [ ] #4 Rejects non-BOOKMOBI/TEXtREAd files with a typed error (not a panic)
- [ ] #5 Unit tests parse a synthetic record 0 with an EXTH block and assert every extracted field; docs reference §2.2 in code
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Add `crates/dedrm-formats/src/mobi.rs` (register in lib.rs). Provide `MobiHeader` with: `compression` (0x00 u16), `text_record_count` (0x08), `encryption_type` (0x0C), `is_textread`, `mobi_length` (0x14), `mobi_version` (0x68), `codepage` (0x1C), `exth_flag` (0x80), `drm` block (0xA8: ptr/count/size/flags), and adjusted `extra_data_flags` (0xF2 when mobi_length>=0xE4 && mobi_version>=5; low bit cleared unless compression==17480). Parse EXTH (at 16+mobi_length when exth_flag&0x40) into a `BTreeMap<u32,Vec<u8>>`. Add `pid_meta()` reconstructing (rec209, token) per getPIDMetaInfo (walk rec209 in 5-byte groups: tag byte + BE-u32 key -> concat referenced values). `parse(record0, type_creator)` rejects non-BOOKMOBI/TEXtREAd with FormatError::BadMagic; `from_image(data)` runs PalmDb::parse first. TEXtREAd stops after the 3 PalmDoc fields. All big-endian, bounds-checked helpers, no unwrap on real paths. Unit tests: synthetic BOOKMOBI record 0 with EXTH (incl. 209 + referenced record) asserting every field + pid_meta; a TEXtREAd case; and a bad-magic rejection.
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
