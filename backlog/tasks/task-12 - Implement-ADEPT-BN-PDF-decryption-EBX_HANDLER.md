---
id: TASK-12
title: Implement ADEPT + B&N PDF decryption (EBX_HANDLER)
status: Done
assignee:
  - Kessriga Jeükal
created_date: '2026-07-03 19:58'
updated_date: '2026-07-04 10:37'
labels:
  - schemes
  - pdf
  - adept
  - ignoble
milestone: m-2
dependencies:
  - TASK-9
  - TASK-11
references:
  - docs/DEDRM_SCHEMES.md
  - ../../external/DeDRM_tools/DeDRM_plugin/ineptpdf.py
  - ../../external/DeDRM_tools/DeDRM_plugin/ignoblepdf.py
modified_files:
  - crates/flamberge-formats/src/pdf/mod.rs
  - crates/flamberge-formats/src/pdf/document.rs
  - crates/flamberge-schemes/src/lib.rs
  - crates/flamberge-schemes/src/pdf_common.rs
  - crates/flamberge-schemes/src/adept.rs
  - crates/flamberge-schemes/src/ignoble.rs
  - crates/flamberge-schemes/src/epub_common.rs
  - CLAUDE.md
priority: low
ordinal: 12000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement the EBX_HANDLER decrypt path for both flamberge-schemes::adept::decrypt_pdf and flamberge-schemes::ignoble::decrypt_pdf, on top of the PDF model (task-11) and RSA (task-9).

Flow (§7.4): read the `/Encrypt` dict; for EBX_HANDLER, base64-decode `ADEPT_LICENSE`, raw-inflate (-15), parse the adept XML, RSA-decrypt the `encryptedKey`, strip PKCS#7, take the last 16 bytes as book key (B&N uses its 16-byte user key directly with a zero-IV AES unwrap of the license key instead of RSA). Content: RC4 per object with a per-object key: genkey_v2 = MD5(book_key ‖ objid_LE[:3] ‖ genno_LE[:2]) truncated to min(len+5,16); genkey_v3 = XOR objid^0x3569ac, genno^0xca96, interleave + 'sAlT'. Decipher every string/stream, then serialize a clean PDF. Note the Adobe.APS principal-key path is optional/out-of-scope unless a fixture needs it. Original: ineptpdf.py, ignoblepdf.py.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 ADEPT PDF: ADEPT_LICENSE is base64+inflate parsed, RSA-unwrapped to the 16-byte book key (last 16 after PKCS#7 strip)
- [x] #2 B&N PDF: the 16-byte user key unwraps the license key via zero-IV AES-CBC to the book key
- [x] #3 Per-object RC4 keys are derived by genkey_v2 and genkey_v3 (objid^0x3569ac, genno^0xca96, 'sAlT') and every string/stream is deciphered
- [x] #4 A clean, decrypted PDF is serialized (gen 0, /Encrypt removed) and re-opens without a password
- [x] #5 Integration test decrypts a synthesized EBX_HANDLER PDF and asserts extracted text; Adobe.APS documented as out of scope
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
## Approach

Key insight: the PDF book-key **unwrap** is identical to each scheme's existing
EPUB unwrap (`recover_book_key`/`unwrap_book_key`) — ADEPT's raw-RSA `[-17]==0`
last-16 rule, B&N's AES zero-IV + PKCS#7 last-16 rule. Only the wrapped-key
*source* and the *content cipher* are new. So reuse those private fns.

### formats/pdf — add a decipher hook (mirrors ineptpdf `getobj`+`decipher_all`)
- Add `Decipher = Box<dyn Fn(u32,u16,&[u8])->Vec<u8>>` and
  `PdfDocument::set_decipher(f)`: clears the object cache, records the `/Encrypt`
  objid to skip.
- Apply in `parse_indirect_at` (uncompressed objects only, matching ineptpdf which
  never re-deciphers ObjStm members): recurse Str/Array/Dict, and for a Stream
  decipher its `rawdata` (not its dict). The serializer already writes deciphered
  `rawdata` verbatim with `/Filter` intact → re-parse inflates it.

### schemes/pdf_common (new module, like epub_common)
- `EbxLicense { wrapped: Vec<u8>, version: u8 }`.
- `ebx_license(doc)`: resolve `/Encrypt`; require `/Filter == EBX_HANDLER` (else
  `NotThisScheme`); read `ADEPT_LICENSE` string → base64 → raw-inflate(-15) →
  namespace-aware XML → `encryptedKey` base64. Version = 3 if `/V == 3` else 2.
- `genkey_v2/v3(book_key, objid, genno)` → per §7.4/§4.5.
- `decrypt_pdf(doc, book_key, version)`: set an RC4 decipher closure, serialize.

### schemes/adept::decrypt_pdf + ignoble::decrypt_pdf
- Guard `%PDF` magic → `PdfDocument::parse` → `ebx_license`.
- Discriminate by `wrapped.len()`: B&N wraps to 48 bytes (AES), ADEPT to the RSA
  modulus size. ignoble claims len==48 else `NotThisScheme`; adept claims len!=48.
- `recover_book_key(&wrapped, keys)` (existing) → `pdf_common::decrypt_pdf` →
  `DecryptedBook { extension: "pdf" }`.

### Tests
- Unit: genkey_v2/v3 vectors; decipher round-trip; scheme discrimination.
- Integration (AC#5): synth an EBX_HANDLER PDF (indirect `/Encrypt`, one RC4'd
  string + one Flate+RC4 stream) for both ADEPT (RSA-wrapped) and B&N
  (AES-wrapped); decrypt via top-level `decrypt(_, "pdf", _)`; re-parse output and
  assert the string + inflated stream text; assert `/Encrypt` gone. Adobe.APS/AES
  branch documented out of scope.

Autonomous execution: recording plan and proceeding (user pre-approved "implement
the next task").
<!-- SECTION:PLAN:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Implemented the EBX_HANDLER decrypt path for ADEPT and B&N PDFs (§7.4 / §4.5).
PR #13 (branch `feat/task-12-pdf-decrypt`).

**formats/pdf:** added `PdfDocument::set_decipher(Decipher)` — a scheme-supplied
`Fn(objid, genno, bytes) -> plaintext` applied to each uncompressed object while
reading (recursing Str/Array/Dict and a Stream's body), mirroring
`ineptpdf.getobj` + `decipher_all`. ObjStm members aren't re-deciphered; the
`/Encrypt` object is skipped; installing it clears the object caches. The
existing `PdfSerializer` writes the deciphered (still `/Filter`-encoded) bytes
verbatim, so no re-compression is needed.

**schemes/pdf_common (new):** reads the `/Encrypt` `ADEPT_LICENSE` (base64 → raw
inflate −15 → adept XML → `encryptedKey`), derives the per-object RC4 key
(`genkey_v2`/`v3`, version by `/V`), installs the decipher, re-serializes.

**adept/ignoble::decrypt_pdf:** reuse each scheme's existing `recover_book_key`
unchanged — the PDF book-key unwrap is byte-identical to the EPUB one (ADEPT RSA
`[-17]==0` last-16; B&N zero-IV AES + PKCS#7 last-16). Dispatch discriminates by
wrapped-key length (48-byte AES ⇒ B&N, RSA modulus ⇒ ADEPT).

**Out of scope (documented):** the `Adobe.APS`/Standard-V4 AES content branch
(`genkey_v4`) and the German Onleihe principal key — RC4 covers retail EBX.

**Tests:** 11 new — genkey layout vectors, namespaced `encryptedKey` extraction,
and end-to-end decryption of synthesized EBX_HANDLER PDFs (RC4'd Flate stream +
RC4'd string) for ADEPT (RSA, v2 + v3) and B&N (AES) through the top-level
`decrypt(_, "pdf", _)`, asserting recovered text and stripped `/Encrypt`. No-key
and unencrypted paths assert deterministic `NoKeyWorked`. Workspace fmt / clippy
-D warnings / test all green.

Follow-up noted: the pre-existing `unwrap_book_key_wrong_key_is_none_not_error`
tests in adept.rs/ignoble.rs are ~1/256 probabilistic (random RSA keys); left
as-is (out of scope), but the new PDF no-key test was written deterministically
to avoid adding to that surface.

**Update:** the pre-existing ~1/256-flaky `wrong_key`/`unwrap_book_key_wrong_key_is_none_not_error` tests in adept.rs (random RSA keys) were also made deterministic in this PR — every `thread_rng` was replaced with a per-call-site seeded `StdRng` (commit `514a418`). ignoble.rs tests were already deterministic (pure name+CC key generation). Workspace suite now passes reproducibly across repeated runs.
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
