---
id: TASK-16
title: Adobe ADEPT key extraction (macOS activation.dat + Windows DPAPI)
status: To Do
assignee: []
created_date: '2026-07-03 20:00'
labels:
  - keys
  - adept
milestone: m-4
dependencies: []
references:
  - docs/DEDRM_SCHEMES.md
  - ../../external/DeDRM_tools/DeDRM_plugin/adobekey.py
modified_files:
  - crates/flamberge-keys/src/adobe.rs
priority: low
ordinal: 16000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement flamberge-keys::adobe::extract_keys to recover the ADEPT RSA private key DER from the local Adobe Digital Editions install.

macOS (fully offline): locate `activation.dat` under `~/Library/Application Support/Adobe/Digital Editions`, XPath the `adept:privateLicenseKey`, base64-decode, strip the 26-byte header → DER. Windows (feature-gated `windows-dpapi`): build the 32-byte entropy (volume serial + CPUID leaf-0 vendor + leaf-1 signature low-3-bytes + username), CryptUnprotectData the Device `key` → keykey, then AES-128-CBC (zero IV) decrypt each `privateLicenseKey` and strip 26-byte header + PKCS#7. Return DER keys into KeyStore.adept_keys. Off-supported-platform, return a clear Unsupported error. Spec: docs/DEDRM_SCHEMES.md §7.2. Original: adobekey.py.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 macOS path parses activation.dat, extracts privateLicenseKey, strips 26 bytes, and yields a valid PKCS#1 RSAPrivateKey DER (parseable by the RSA code)
- [ ] #2 Windows path is feature-gated: entropy is packed as documented, DPAPI recovers keykey, and AES-CBC + 26-byte/PKCS#7 strip yields the DER key
- [ ] #3 Unsupported platforms return a clear Unsupported error, not a panic
- [ ] #4 Extracted keys populate KeyStore.adept_keys and decrypt an ADEPT EPUB in an integration test (macOS or with a fixture activation.dat)
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
