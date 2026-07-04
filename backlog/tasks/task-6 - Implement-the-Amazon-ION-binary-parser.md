---
id: TASK-6
title: Implement the Amazon ION binary parser
status: Done
assignee: []
created_date: '2026-07-03 19:56'
updated_date: '2026-07-03 23:47'
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
- [x] #1 VarUInt/VarInt decode correctly incl. multi-byte and sign; type-descriptor parsing handles VarUInt-length, null, bool-in-nibble, and ordered-struct L==1
- [x] #2 Struct/list navigation (step in/out) respects the container byte budget and reads struct field ids
- [x] #3 Annotations resolve via the symbol table; the ProtectedData shared table is seeded with the full ordered SYM_NAMES and system symbols 1-9
- [x] #4 BLOB/CLOB accessors return raw bytes; strings decode as UTF-8; ints/symbols are big-endian magnitudes
- [x] #5 Unit tests parse a hand-built ION struct with an annotation, a nested list, and a BLOB, asserting names and values
<!-- AC:END -->



## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Port ion.py::BinaryIonParser into flamberge-formats::ion as a borrowing pull parser (BinaryIonParser<'a> over &[u8], index cursor for seek/reset). Free functions read_varuint/read_varint for standalone decode; type-descriptor parsing (VarUInt-length 0xE, null 0xF, bool-in-nibble, ordered-struct L==1); big-endian int/symbol magnitudes; UTF-8 strings; BLOB/CLOB accessors. Symbol table seeded with the 10 system symbols plus a catalog holding the full ordered ProtectedData SYM_NAMES; the in-stream $ion_symbol_table directive imports it so annotations resolve. Container navigation via step_in/step_out with the localremaining byte budget. TDD: encoder helpers in tests build hand-crafted ION streams.</planSet>
<parameter name="notesAppend">Implemented in crates/flamberge-formats/src/ion.rs. Faithful port of ion.py's BinaryIonParser state machine (BeforeField/BeforeTid/BeforeValue/AfterValue/Eof) plus the symbol-table import machinery (parse_symbol_table/gather_imports/read_import) and the ProtectedData catalog.

Two deliberate, documented deviations from ion.py, both safe for KFX: (1) null values set valueisnull=true on the 0xF nibble (ion.py leaves it implicit) so is_null() is meaningful; (2) reads return typed FormatError instead of raising, with Truncated treated as clean-EOF in read_field_id. Imported symbols get SIDs starting at 10 (system symbols 1-9), matching ion.py's [None]*10 + append — the spec prose's "SID 11" is off by one; the code is authoritative. Float/decimal/timestamp are recognised and skipped but not decoded (not needed for KFX).

The subtle correctness point is symbol-table reentrancy: parse_symbol_table runs inside has_next and itself calls next/step_in/step_out; the needhasnext one-shot latch is what stops the first next() from double-advancing. 8 unit tests, full gate green (clippy -D warnings, fmt --check, 71 workspace tests). No unwrap/panic on non-test paths.</notesAppend>
<parameter name="finalSummary">Implemented the Amazon ION binary pull parser (flamberge-formats::ion, TASK-6), a faithful Rust port of DeDRM's ion.py::BinaryIonParser sufficient for KFX vouchers and content.

What changed:
- flamberge-formats/src/ion.rs: replaced the stub with a full BinaryIonParser<'a>. Public API: new, add_to_catalog, add_protected_data_table, next, step_in/step_out, type_name, field_name, int_value, string_value, symbol_value, lob_value, bool_value, is_null, reset; free read_varuint/read_varint; protected_data_symbols() (full ordered SYM_NAMES incl. VoucherEnvelope@{2..=28}.0 and the fixed numeric-version tail).
- Covers: BVM handling, type descriptors (0xE VarUInt length, 0xF null, bool-in-nibble, ordered-struct L==1), VarUInt/VarInt (base-128, VarInt sign bit), big-endian int/symbol magnitudes, UTF-8 strings, BLOB/CLOB raw bytes, annotation wrappers (first SID = type name), symbol table with system symbols 1-9 plus the ProtectedData shared import resolved from an in-stream $ion_symbol_table directive, and list/struct navigation honoring the localremaining byte budget.
- CLAUDE.md Status section updated (ion → real+tested; next slice = TASK-7).

Tests: 8 new unit tests using test-only ION encoder helpers, incl. the AC #5 end-to-end fixture (symbol-table import → annotated Voucher struct → nested annotated KeySet list → BLOB). Full gate green: cargo build/test (28 formats, 71 workspace), clippy --workspace --all-targets -D warnings, fmt --check.

Follow-up: TASK-7 (KFX voucher unwrap + content decryption, §3.3-3.4) consumes this parser, then the kfx_zip container feeds it.
<!-- SECTION:PLAN:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 cargo build succeeds with no warnings
- [x] #2 cargo test passes (unit and integration)
- [x] #3 cargo clippy passes with no warnings
- [x] #4 no panic!/unwrap/expect on non-test code paths
- [x] #5 behavior matches docs/DEDRM_SCHEMES.md and code cites the relevant section
- [x] #6 public items have doc comments
<!-- DOD:END -->
