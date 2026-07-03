---
id: TASK-7
title: Implement KFX voucher unwrap + content decryption
status: To Do
assignee: []
created_date: '2026-07-03 19:56'
labels:
  - schemes
  - formats
  - kindle
  - kfx
milestone: m-1
dependencies:
  - TASK-6
references:
  - docs/DEDRM_SCHEMES.md
  - ../../external/DeDRM_tools/DeDRM_plugin/kfxdedrm.py
  - ../../external/DeDRM_tools/DeDRM_plugin/ion.py
modified_files:
  - crates/flamberge-formats/src/kfx_zip.rs
  - crates/flamberge-schemes/src/kfx.rs
  - crates/flamberge-crypto/src/kdf.rs
priority: medium
ordinal: 7000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement KFX-ZIP handling in flamberge-formats::kfx_zip (find DRMION + voucher members by magic, strip DRMION 8+8) and the decrypt path in flamberge-schemes::kfx using the ION parser (task-6) and crypto primitives.

Voucher key chain (§3.3): split each candidate PID into (dsn, secret) by trying the length splits; build `shared = "PIDv3"+encAlg+encTransform+hashAlg` + sorted lock_parameters applied with dsn/secret; `obfuscate(shared, version)` (port OBFUSCATION_TABLE byte-for-byte); `kek = HMAC_SHA256(sharedsecret, "PIDv3")`; AES-256-CBC decrypt + PKCS#7 unpad the voucher; extract the 16-byte content key from the KeySet/SecretKey (AES/RAW/encoded). Content (§3.4): AES-128-CBC per page with per-page IV + PKCS#7; decompress Compressed pages (1-byte 0x00 UseFilter then LZMA-alone). Repackage the zip with decrypted members. Add an `lzma` dependency (alone/legacy format). Spec: docs/DEDRM_SCHEMES.md §3. Original: kfxdedrm.py, ion.py (DrmIon, DrmIonVoucher).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 KFX-ZIP members are located by magic; DRMION payload is stripped of the 8-byte prefix/suffix and the voucher member is identified by ProtectedData
- [ ] #2 PID is split across the documented length combinations and the voucher KEK is derived via obfuscate + HMAC-SHA256; OBFUSCATION_TABLE is ported byte-for-byte and covered by a test
- [ ] #3 Voucher AES-256-CBC unwrap + PKCS#7 yields the KeySet, and the 16-byte AES/RAW content key is extracted
- [ ] #4 Encrypted pages are AES-128-CBC decrypted with per-page IV; Compressed pages are LZMA-alone decompressed after stripping the 0x00 filter byte
- [ ] #5 A wrong PID fails the PKCS#7 padding check and the next candidate is tried; output is a repackaged zip
- [ ] #6 Unit/integration test exercises the voucher key chain against known vectors or a synthesized voucher
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
