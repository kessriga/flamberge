---
id: TASK-11
title: Implement the PDF tokenizer / object model
status: Done
assignee: []
created_date: '2026-07-03 19:58'
updated_date: '2026-07-04 09:23'
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
  - crates/flamberge-formats/src/pdf.rs
priority: low
ordinal: 11000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement flamberge-formats::pdf: a pdfminer-style tokenizer and object model sufficient for ADEPT/B&N decryption and clean re-serialization. Cover the lexer (names, numbers, strings incl. escapes, hex strings, arrays, dicts, streams), the object graph with indirect references, classic `xref` tables and PDF-1.5 cross-reference streams, object streams (ObjStm), and stream filters FlateDecode/LZWDecode/ASCII85Decode with the PNG-up predictor (12). Expose the `/Encrypt` dict and `/ID`. Provide a serializer that writes a decrypted PDF (forcing gen 0, dropping `/Encrypt`).

This is a large module; keep decryption out of scope (task-12). Port incrementally but land a working parse+reserialize of unencrypted PDFs first. Spec: docs/DEDRM_SCHEMES.md §7.4. Original: ineptpdf.py.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Lexer + object model parse names/numbers/strings/hex/arrays/dicts/streams and resolve indirect references
- [x] #2 Both classic xref tables and xref streams (plus ObjStm) are supported; trailer exposes /Encrypt and /ID
- [x] #3 Flate/LZW/ASCII85 stream filters decode, including Predictor 12
- [x] #4 Serializer round-trips an unencrypted PDF (parse -> write -> re-parse) preserving object content
- [x] #5 Unit tests cover the lexer, an xref-stream document, and a filter-decode round trip
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Port ineptpdf.py's pdfminer-derived parser to Rust (decryption deferred to TASK-12).

1. Object model: `Object` enum (Null/Bool/Int/Real/Str/Name/Array/Dict/Stream/Ref/Keyword) + `PdfStream{dict,rawdata,objid,genno}`; `Dict = BTreeMap<String,Object>`. Resolve helpers.
2. Lexer over `&[u8]` cursor: whitespace/comments, names (#xx), literal strings (balanced parens, octal/char escapes), hex strings, numbers (int/real), keywords, `<< >> [ ]` delimiters.
3. Recursive-descent object parser with `n g R` reference lookahead; `stream` keyword reads raw bytes by /Length (resolving indirect Length) then confirms `endstream`.
4. XRef: classic `xref` table + PDF-1.5 xref streams; follow /Prev and /XRefStm. Trailer exposes /Root, /Encrypt, /ID, /Size.
5. Lazy `get_object` with cache; ObjStm member extraction (flat parse, index = N*2+i).
6. Stream filters: FlateDecode (zlib), LZWDecode (variable-width, early change), ASCII85Decode; PNG predictor (Predictor >=10, all row filters) + none.
7. Serializer: classic xref output, force gen 0, drop /Encrypt, ObjStm containers emitted as `(deleted)`, compressed members promoted to top-level objects.
8. Tests: lexer tokens, classic-xref round-trip, xref-stream doc parse, filter-decode round trips (flate/lzw/ascii85/predictor-12).

Note: original's PNG predictor has a latent py3 bug (int==bytes never matches, so Up prediction is skipped); this port implements PNG prediction correctly per §7.4's stated "PNG-up" intent.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented flamberge-formats::pdf as a from-scratch, in-memory port of ineptpdf.py's pdfminer-derived parser (streaming buffer machinery collapsed to a cursor over &[u8]). Lexer covers whitespace/comments, /Name #xx escapes, literal strings (balanced parens, octal+char escapes, line continuations), zero-padded hex strings, int/real numbers, << >> [ ] delimiters, keywords. Object model: Object enum + PdfStream with recursive-descent parser and bounded 'n g R' reference look-ahead; stream bodies read by /Length (resolving indirect Length) with an endstream-scan fallback. XRef: classic tables + PDF-1.5 xref streams following /Prev and /XRefStm (cycle-guarded); trailer exposes /Root,/Encrypt,/ID,/Size. Lazy get_object with cache; ObjStm member extraction at flat index 2*N+index. Filters: FlateDecode(zlib), LZWDecode(variable-width MSB-first, EarlyChange=1, KwKwK), ASCII85Decode; predictors TIFF-2 and full PNG row-filter set (original's PNG predictor is a py3 int==bytes no-op bug, fixed here per §7.4 PNG-up intent). PdfSerializer: classic-xref output, gen 0 forced, /Encrypt dropped, xref streams dropped, ObjStm containers dissolved.

Verification: fmt/clippy clean, full workspace tests pass (15 new pdf unit tests). Validated end-to-end against real macOS PDFs (Xcode Acknowledgments.pdf: 821 objects all readable, serialize+reparse->821; others clean round-trips).

Branch was cut from a stale local main (session-start git pull silently failed with 'Cannot rebase onto multiple branches'); rebased onto origin/main (dfa5293, which merged TASK-10) before finalizing. No file overlap with TASK-10.
<!-- SECTION:NOTES:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 cargo build succeeds with no warnings
- [x] #2 cargo test passes (unit and integration)
- [x] #3 cargo clippy passes with no warnings
- [x] #4 no panic!/unwrap/expect on non-test code paths
- [x] #5 behavior matches docs/DEDRM_SCHEMES.md and code cites the relevant section
- [x] #6 public items have doc comments
<!-- DOD:END -->
