---
id: TASK-6
title: Implement the Amazon ION binary parser
status: To Do
assignee: []
created_date: '2026-07-03 19:56'
labels:
  - formats
  - kindle
  - kfx
  - ion
milestone: m-1
dependencies: []
references:
  - docs/DEDRM_SCHEMES.md
  - ../../external/DeDRM_tools/DeDRM_plugin/ion.py
modified_files:
  - crates/flamberge-formats/src/ion.rs
priority: medium
ordinal: 6000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement flamberge-formats::ion as a pull parser sufficient for KFX vouchers and content. Cover: the BVM, type-descriptor byte (type-id nibble + length nibble, with 0xE VarUInt-length and 0xF null specials, bool-in-length-nibble, struct L==1 ordered-struct), VarUInt/VarInt (big-endian base-128, high-bit terminator; VarInt sign bit 0x40), big-endian int/symbol magnitudes, UTF-8 strings, BLOB/CLOB raw bytes, and annotation wrappers (first annotation SID = type name). Implement the symbol table with the 10 system symbols plus the fixed `ProtectedData` shared table (port the full ordered SYM_NAMES incl. the appended VoucherEnvelope@N.0 entries) so annotations resolve to names like `com.amazon.drm.Voucher@1.0`. Provide container navigation (step in/out, field ids in structs) with the localremaining byte-budget.

Spec: docs/DEDRM_SCHEMES.md §3.2. Original: ion.py.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 VarUInt/VarInt decode correctly incl. multi-byte and sign; type-descriptor parsing handles VarUInt-length, null, bool-in-nibble, and ordered-struct L==1
- [ ] #2 Struct/list navigation (step in/out) respects the container byte budget and reads struct field ids
- [ ] #3 Annotations resolve via the symbol table; the ProtectedData shared table is seeded with the full ordered SYM_NAMES and system symbols 1-9
- [ ] #4 BLOB/CLOB accessors return raw bytes; strings decode as UTF-8; ints/symbols are big-endian magnitudes
- [ ] #5 Unit tests parse a hand-built ION struct with an annotation, a nested list, and a BLOB, asserting names and values
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
