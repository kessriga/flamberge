---
id: TASK-11
title: Implement the PDF tokenizer / object model
status: To Do
assignee: []
created_date: '2026-07-03 19:58'
labels:
  - formats
  - pdf
  - adept
  - ignoble
milestone: m-2
dependencies: []
references:
  - docs/DEDRM_SCHEMES.md
  - ../../external/DeDRM_tools/DeDRM_plugin/ineptpdf.py
modified_files:
  - crates/dedrm-formats/src/pdf.rs
priority: low
ordinal: 11000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement dedrm-formats::pdf: a pdfminer-style tokenizer and object model sufficient for ADEPT/B&N decryption and clean re-serialization. Cover the lexer (names, numbers, strings incl. escapes, hex strings, arrays, dicts, streams), the object graph with indirect references, classic `xref` tables and PDF-1.5 cross-reference streams, object streams (ObjStm), and stream filters FlateDecode/LZWDecode/ASCII85Decode with the PNG-up predictor (12). Expose the `/Encrypt` dict and `/ID`. Provide a serializer that writes a decrypted PDF (forcing gen 0, dropping `/Encrypt`).

This is a large module; keep decryption out of scope (task-12). Port incrementally but land a working parse+reserialize of unencrypted PDFs first. Spec: docs/DEDRM_SCHEMES.md §7.4. Original: ineptpdf.py.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Lexer + object model parse names/numbers/strings/hex/arrays/dicts/streams and resolve indirect references
- [ ] #2 Both classic xref tables and xref streams (plus ObjStm) are supported; trailer exposes /Encrypt and /ID
- [ ] #3 Flate/LZW/ASCII85 stream filters decode, including Predictor 12
- [ ] #4 Serializer round-trips an unencrypted PDF (parse -> write -> re-parse) preserving object content
- [ ] #5 Unit tests cover the lexer, an xref-stream document, and a filter-decode round trip
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
