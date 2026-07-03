---
id: TASK-12
title: Implement ADEPT + B&N PDF decryption (EBX_HANDLER)
status: To Do
assignee: []
created_date: '2026-07-03 19:58'
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
  - crates/dedrm-schemes/src/adept.rs
  - crates/dedrm-schemes/src/ignoble.rs
priority: low
ordinal: 12000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement the EBX_HANDLER decrypt path for both dedrm-schemes::adept::decrypt_pdf and dedrm-schemes::ignoble::decrypt_pdf, on top of the PDF model (task-11) and RSA (task-9).

Flow (§7.4): read the `/Encrypt` dict; for EBX_HANDLER, base64-decode `ADEPT_LICENSE`, raw-inflate (-15), parse the adept XML, RSA-decrypt the `encryptedKey`, strip PKCS#7, take the last 16 bytes as book key (B&N uses its 16-byte user key directly with a zero-IV AES unwrap of the license key instead of RSA). Content: RC4 per object with a per-object key: genkey_v2 = MD5(book_key ‖ objid_LE[:3] ‖ genno_LE[:2]) truncated to min(len+5,16); genkey_v3 = XOR objid^0x3569ac, genno^0xca96, interleave + 'sAlT'. Decipher every string/stream, then serialize a clean PDF. Note the Adobe.APS principal-key path is optional/out-of-scope unless a fixture needs it. Original: ineptpdf.py, ignoblepdf.py.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ADEPT PDF: ADEPT_LICENSE is base64+inflate parsed, RSA-unwrapped to the 16-byte book key (last 16 after PKCS#7 strip)
- [ ] #2 B&N PDF: the 16-byte user key unwraps the license key via zero-IV AES-CBC to the book key
- [ ] #3 Per-object RC4 keys are derived by genkey_v2 and genkey_v3 (objid^0x3569ac, genno^0xca96, 'sAlT') and every string/stream is deciphered
- [ ] #4 A clean, decrypted PDF is serialized (gen 0, /Encrypt removed) and re-opens without a password
- [ ] #5 Integration test decrypts a synthesized EBX_HANDLER PDF and asserts extracted text; Adobe.APS documented as out of scope
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
