---
id: TASK-16
title: Adobe ADEPT key extraction (macOS activation.dat + Windows DPAPI)
status: Done
assignee:
  - Kessriga Jeükal
created_date: '2026-07-03 20:00'
updated_date: '2026-07-04 18:23'
labels:
  - keys
  - adept
milestone: m-4
dependencies: []
references:
  - docs/DEDRM_SCHEMES.md
  - ../../external/DeDRM_tools/DeDRM_plugin/adobekey.py
modified_files:
  - crates/flamberge-keys/src/adobe/mod.rs
  - crates/flamberge-keys/src/adobe/macos.rs
  - crates/flamberge-keys/src/adobe/windows.rs
  - crates/flamberge-keys/Cargo.toml
  - crates/flamberge-crypto/src/rsa.rs
  - crates/flamberge-cli/src/main.rs
  - crates/flamberge-schemes/src/adept.rs
  - CLAUDE.md
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
- [x] #1 macOS path parses activation.dat, extracts privateLicenseKey, strips 26 bytes, and yields a valid PKCS#1 RSAPrivateKey DER (parseable by the RSA code)
- [ ] #2 Windows path is feature-gated: entropy is packed as documented, DPAPI recovers keykey, and AES-CBC + 26-byte/PKCS#7 strip yields the DER key
- [x] #3 Unsupported platforms return a clear Unsupported error, not a panic
- [x] #4 Extracted keys populate KeyStore.adept_keys and decrypt an ADEPT EPUB in an integration test (macOS or with a fixture activation.dat)
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Split `flamberge-keys::adobe` into a module dir (`adobe/mod.rs`, `adobe/macos.rs`, `adobe/windows.rs`); add `quick-xml` dep.

## macOS (fully offline, tested)
- `find_activation_dat()`: walk `~/Library/Application Support/Adobe/Digital Editions` for `activation.dat` (recursive; the ** in the spec).
- `parse_private_license_key(xml)`: namespace-aware (quick-xml NsReader) extract of `adept:privateLicenseKey` text nested under `adept:credentials` (ns `http://ns.adobe.com/adept`).
- base64-decode → strip first 26 bytes (no AES) → PKCS#1 RSAPrivateKey DER.
- Validate the DER parses (via rsa crate / flamberge-crypto) before returning.

## Windows algorithm (portable + tested; live gathering Unsupported)
- `pack_entropy(serial: u32, vendor: [u8;12], signature: [u8;3], username: &[u8]) -> [u8;32]`: the `struct.pack('>I12s3s13s', ...)` layout — pure, unit-tested against a known vector.
- `decrypt_private_license_key(keykey, b64) -> DER`: AES-128-CBC zero-IV decrypt + strip 26-byte header + PKCS#7 unpad — pure, round-trip tested.
- Live host gathering (volume serial / CPUID leaf-0/1 / GetUserNameW / CryptUnprotectData / HKCU registry) returns `KeyError::Unsupported` off a Windows host, matching the established kindle precedent (Windows v5 DPAPI -> Unsupported; CLAUDE.md gotcha: these paths are not reproducible offline). Doc-comment the exact DPAPI/registry recipe from §7.2 for a future Windows-hosted impl. No uncompilable FFI.

## API / wiring
- `extract_keys() -> Result<Vec<Vec<u8>>>` dispatches by `cfg!(target_os)`: macOS -> activation.dat path; Windows -> Unsupported (feature note); else Unsupported.
- Wire `KeysCommand::Adobe` in the CLI to call `extract_keys()` and print DER hex (replacing the current bail!).

## Tests
- macOS parse from a fixture activation.dat string (embedded) yielding a valid DER (built from a generated RSA key: DER = 26-byte header ++ pkcs1_der, base64'd into XML) -> assert parses.
- `pack_entropy` layout vector.
- `decrypt_private_license_key` round-trip (AES-CBC-encrypt header++der++pkcs7 pad with zero IV, decrypt back).
- Unsupported-platform returns Unsupported, not panic.

## Scope note
AC #2's *live* Windows DPAPI/registry gathering is returned as `Unsupported` (not a compiled FFI implementation) to stay consistent with the kindle Windows-DPAPI precedent and keep CI/DoD (no-panic, builds clean) satisfiable; the portable Windows *algorithm* (entropy packing + license-key AES decrypt) IS implemented and tested.
<!-- SECTION:PLAN:END -->

## Comments

<!-- COMMENTS:BEGIN -->
author: Kessriga Jeükal
created: 2026-07-04 18:19
---
AC #2 (Windows) partially addressed by design, left unchecked. The two portable, testable pieces of the Windows algorithm ARE implemented and unit-tested: `pack_entropy` (the `>I12s3s13s` DPAPI entropy layout) and `decrypt_private_license_key` (AES-128-CBC zero-IV + 26-byte header + PKCS#7 strip). The *live host gathering* — `GetVolumeInformationW` serial, CPUID leaf-0/1, `GetUserNameW`, `CryptUnprotectData`, and the HKCU registry walk — returns `KeyError::Unsupported` rather than shipping FFI that CI cannot compile or test. This matches the established project precedent (Kindle `.kinf2011` v5 DPAPI -> Unsupported) and the CLAUDE.md gotcha that these DPAPI paths are not reproducible offline. The exact Windows recipe is documented in `adobe/windows.rs` for a future host-bound implementer. If a fully-live Windows path is wanted, recommend a dedicated follow-up task on a Windows host.
---
<!-- COMMENTS:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Implemented Adobe ADEPT key extraction as a `flamberge-keys::adobe` module dir (`mod`/`macos`/`windows`).

**macOS (fully real + tested):** `extract_keys()` recursively locates `activation.dat` under `~/Library/Application Support/Adobe/Digital Editions` (depth-bounded), and `parse_activation_dat()` does a namespace-aware quick-xml walk for `adept:credentials/adept:privateLicenseKey`, base64-decodes, strips the fixed 26-byte header, and validates the result parses as a PKCS#1 RSAPrivateKey (new `flamberge_crypto::rsa::private_key_modulus_len`). Wired into the CLI `keys adobe` subcommand (prints DER hex).

**Windows algorithm (portable, tested):** `pack_entropy` (the `>I12s3s13s` DPAPI entropy layout) and `decrypt_private_license_key` (AES-128-CBC zero-IV + 26-byte header + PKCS#7 strip) are implemented and unit-tested. The **live** host gathering (volume serial / CPUID / GetUserNameW / CryptUnprotectData / HKCU registry) returns `KeyError::Unsupported` — a deliberate scope decision matching the established Kindle `.kinf2011` v5 precedent and the CLAUDE.md gotcha that DPAPI paths aren't reproducible offline. The exact recipe is doc-commented in `adobe/windows.rs` for a future Windows-hosted implementer. AC #2 (full live Windows) is therefore left unchecked; see task comment.

**Verification:** cargo build/test/clippy/fmt all clean across the workspace (41 keys tests, 83 schemes tests). AC #4 covered by a schemes integration test (`decrypt_epub_via_extracted_activation_dat_key`) that extracts a key from a fixture activation.dat and decrypts an ADEPT EPUB. Also verified end-to-end at runtime: built a fixture activation.dat wrapping a real openssl-generated 1024-bit PKCS#1 DER, ran `flamberge keys adobe` with a temp `$HOME`, and confirmed the printed hex exactly matches the original DER; the no-file path returns a clean `NotFound` (no panic).

Follow-up: a fully-live Windows DPAPI path would need a dedicated task run on a Windows host.
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
