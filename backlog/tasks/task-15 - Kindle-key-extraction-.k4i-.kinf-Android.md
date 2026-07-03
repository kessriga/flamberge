---
id: TASK-15
title: Kindle key extraction (.k4i / .kinf / Android)
status: To Do
assignee: []
created_date: '2026-07-03 19:59'
labels:
  - keys
  - kindle
milestone: m-4
dependencies: []
references:
  - docs/DEDRM_SCHEMES.md
  - ../../external/DeDRM_tools/DeDRM_plugin/kindlekey.py
  - ../../external/DeDRM_tools/DeDRM_plugin/androidkindlekey.py
modified_files:
  - crates/flamberge-keys/src/kindle.rs
priority: low
ordinal: 15000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement flamberge-keys::kindle. Load `.k4i` key databases (JSON). Decode `.kinf2011`/`.kinf2018` files: the `/`-delimited record framing, symbol maps + prime rotation, header PBKDF2/AES, and per-value decryption — implement the fully-offline paths (macOS v5 emulated DPAPI, and v6 GCM-as-CTR on both OSes) and clearly surface that Windows v5 requires real DPAPI (feature-gate behind `windows-dpapi`, or return an Unsupported error off-Windows). Extract Android serials from `backup.ab` (ANDROID BACKUP + zlib + tar), `AmazonSecureStorage.xml` (V1 AES-ECB / V2 DES-CBC obfuscation), and `map_data_storage.db` (SQLite). Feed results into KeyStore (kindle DBs + serials).

Spec: docs/DEDRM_SCHEMES.md §6. Original: kindlekey.py, androidkindlekey.py.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 .k4i JSON databases load into the KeyStore; .kinf record framing + symbol/rotation decode is implemented
- [ ] #2 Offline .kinf paths (macOS v5 emulated DPAPI, v6 GCM-as-CTR) decrypt values; Windows v5 DPAPI is feature-gated and returns a clear Unsupported error when unavailable
- [ ] #3 Android serials are extracted from backup.ab, AmazonSecureStorage.xml (V1/V2 obfuscation), and map_data_storage.db
- [ ] #4 Extracted serials/DBs expand the candidate PID list used by the Kindle schemes
- [ ] #5 Unit tests cover the symbol map encode/decode, prime rotation, and v6 value decryption with a synthesized record
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
