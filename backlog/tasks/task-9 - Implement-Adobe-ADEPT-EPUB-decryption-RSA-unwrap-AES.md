---
id: TASK-9
title: Implement Adobe ADEPT EPUB decryption (RSA unwrap + AES)
status: To Do
assignee: []
created_date: '2026-07-03 19:57'
labels:
  - schemes
  - crypto
  - epub
  - adept
milestone: m-2
dependencies:
  - TASK-8
references:
  - docs/DEDRM_SCHEMES.md
  - ../../external/DeDRM_tools/DeDRM_plugin/ineptepub.py
modified_files:
  - crates/flamberge-crypto/src/rsa.rs
  - crates/flamberge-schemes/src/adept.rs
priority: medium
ordinal: 9000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Add RSA PKCS#1 v1.5 private-decrypt to flamberge-crypto (add the `rsa` crate; parse a PKCS#1 RSAPrivateKey DER) and implement flamberge-schemes::adept::decrypt_epub on top of the OCF layer (task-8).

Flow (§7.3): RSA-decrypt the base64 `encryptedKey` from rights.xml with the user key; validate via the byte-at-index-(-17)==0x00 rule and take the last 16 bytes as the AES content key. For each encrypted file: AES-128-CBC decrypt using the first 16 ciphertext bytes as IV over the remainder, strip PKCS#7, then raw-inflate (windowBits -15) with a graceful pass-through when a member was stored uncompressed. Repackage via the OCF writer. Spec: docs/DEDRM_SCHEMES.md §7.1–7.3. Original: adobekey.py (key form), ineptepub.py.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 flamberge-crypto exposes RSA PKCS#1 v1.5 private-decrypt over a PKCS#1 RSAPrivateKey DER, with a unit test
- [ ] #2 The content key is recovered from rights.xml and validated by the -17==0x00 separator rule (last 16 bytes)
- [ ] #3 Encrypted files decrypt via AES-128-CBC (IV = first 16 ciphertext bytes), PKCS#7 strip, then raw inflate; stored members pass through
- [ ] #4 Unencrypted/non-ADEPT EPUBs are reported as such rather than corrupted
- [ ] #5 Integration test decrypts a synthesized ADEPT EPUB (RSA-wrapped key + AES+deflate members) end-to-end and asserts content
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
