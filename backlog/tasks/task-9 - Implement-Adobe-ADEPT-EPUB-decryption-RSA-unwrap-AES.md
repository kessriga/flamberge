---
id: TASK-9
title: Implement Adobe ADEPT EPUB decryption (RSA unwrap + AES)
status: Done
assignee:
  - kessriga
created_date: '2026-07-03 19:57'
updated_date: '2026-07-04 08:35'
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
- [x] #1 flamberge-crypto exposes RSA PKCS#1 v1.5 private-decrypt over a PKCS#1 RSAPrivateKey DER, with a unit test
- [x] #2 The content key is recovered from rights.xml and validated by the -17==0x00 separator rule (last 16 bytes)
- [x] #3 Encrypted files decrypt via AES-128-CBC (IV = first 16 ciphertext bytes), PKCS#7 strip, then raw inflate; stored members pass through
- [x] #4 Unencrypted/non-ADEPT EPUBs are reported as such rather than corrupted
- [x] #5 Integration test decrypts a synthesized ADEPT EPUB (RSA-wrapped key + AES+deflate members) end-to-end and asserts content
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
## Plan

### 1. flamberge-crypto: RSA primitive (`src/rsa.rs`)
- Add `rsa` crate (workspace dep) + `rand` dev-dep for test keygen.
- `private_decrypt_raw(der, ciphertext) -> Vec<u8>`: parse PKCS#1 `RSAPrivateKey` DER (`from_pkcs1_der`), compute textbook `c^d mod n` via `BigUint::modpow`, return the modulus-sized block with leading zeros preserved (OpenSSL `RSA_NO_PADDING` semantics). The ADEPT `[-17]==0x00 → last 16 bytes` unwrap (a.k.a. "PKCS#1 v1.5 unwrap" in §7.1) is applied by the caller, matching `ineptepub.py` (RSA_NO_PADDING + manual separator check).
- Refer to the external crate as `::rsa` inside the module to avoid shadowing.
- Unit test: generate a 1024-bit key, build a `00 02 <pad> 00 <payload>` block, raw-encrypt with the public key, assert round-trip through `private_decrypt_raw`.

### 2. flamberge-schemes: `adept::decrypt_epub`
- Guard: must be a zip + `ocf::is_encrypted_epub` + `OcfEncryption::scheme() == Adept` (172-char key), else `NotThisScheme`.
- Recover book key: base64-decode wrapped key; for each `keys.adept_keys` DER, `private_decrypt_raw` → apply `[-17]==0x00` rule → 16-byte book key; wrong key (separator mismatch) tries next; none → `NoKeyWorked`.
- Per encrypted member (from `encrypted_paths`): AES-128-CBC with IV = first 16 ciphertext bytes over the remainder (equivalent to ref's zero-IV-then-drop-16), strip PKCS#7, then raw inflate (`flate2::read::DeflateDecoder`, windowBits -15); on inflate failure pass through (stored members).
- Repackage via `ocf::repackage`; extension `epub`.
- Add `base64` dep to schemes; `rsa`+`rand` dev-deps for the fixture.

### 3. Unblock dispatch (minimal)
- `.epub` dispatch tries IgnobleEpub before AdeptEpub; the ignoble stub currently returns `Unimplemented` (terminal), blocking ADEPT. Make `ignoble::decrypt_epub` return `NotThisScheme` when the parsed OCF scheme is not `BarnesNoble` (keeps B&N itself stubbed for TASK-10). Needed so the ADEPT slice is reachable via top-level `decrypt()`.

### 4. Tests
- Unit: RSA round-trip; book-key `[-17]` rule (valid + wrong-key); per-file decrypt+inflate + stored pass-through.
- Integration (criterion #5): synthesize an ADEPT EPUB (RSA-wrapped content key in rights.xml + AES+deflate members) and decrypt end-to-end through `schemes::decrypt(_, "epub", _)`, asserting recovered content and that ignoble falls through.

### 5. Verify: build (no warnings), test, clippy -D warnings, fmt. Update CLAUDE.md Status. Rebase onto main, PR.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented. `flamberge-crypto::rsa::private_decrypt_raw` (textbook c^d mod n over PKCS#1 RSAPrivateKey DER, RSA_NO_PADDING semantics) + `adept::decrypt_epub` on the OCF layer. Dispatch subtlety: `.epub` tries IgnobleEpub before AdeptEpub, so the ignoble stub had to return NotThisScheme for non-B&N containers (Unimplemented is terminal in decrypt()) — added live scheme detection to ignoble::decrypt_epub while keeping its B&N crypto stubbed for TASK-10. Verified: cargo build (no warnings), cargo test --workspace (42 pass), clippy -D warnings clean, fmt clean.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
## TASK-9 complete — Adobe ADEPT EPUB decryption

### What shipped
- **`flamberge-crypto::rsa::private_decrypt_raw`** (new `src/rsa.rs`): parses a PKCS#1 `RSAPrivateKey` DER via the `rsa` crate and computes textbook `c^d mod n`, returning the modulus-sized block with leading zeros preserved (OpenSSL `RSA_NO_PADDING`). The ADEPT/PKCS#1-v1.5 unwrap (`[-17]==0x00` → last 16 bytes) is applied by the caller, matching `ineptepub.py` byte-for-byte. Unit tests: padded-block round-trip, ciphertext≥modulus rejection, malformed-DER rejection.
- **`flamberge-schemes::adept::decrypt_epub`**: guard (zip + META markers + 172-char key ⇒ else `NotThisScheme`) → base64-decode wrapped key → try each `keys.adept_keys` DER with the `[-17]` rule → per encrypted member AES-128-CBC (IV = first 16 ciphertext bytes over the remainder), PKCS#7 strip, raw inflate (windowBits -15) with stored-member pass-through → repackage via `ocf::repackage`. Emits a decrypted `.epub`.
- **Dispatch wiring**: `.epub` routes IgnobleEpub → AdeptEpub. Because `Unimplemented` is terminal in `decrypt()`, the ignoble stub would have blocked ADEPT; gave `ignoble::decrypt_epub` live scheme detection (returns `NotThisScheme` for non-B&N) while keeping its B&N crypto stubbed for TASK-10.

### Acceptance criteria — all met
1. RSA private-decrypt over PKCS#1 DER + unit test ✓
2. Book key recovered from rights.xml, validated by `[-17]==0x00` (last 16 bytes) ✓
3. Per-file AES-128-CBC (IV = first 16 ct bytes) + PKCS#7 strip + raw inflate; stored members pass through ✓
4. Non-ADEPT/unencrypted EPUBs reported (`NotThisScheme`/`NoKeyWorked`), not corrupted ✓
5. Synthesized ADEPT EPUB (RSA-wrapped key + AES+deflate members) decrypts end-to-end through top-level `decrypt(_, "epub", _)`, asserting content, dropped DRM META, surviving mimetype ✓

### Verification
`cargo build --workspace` (no warnings), `cargo test --workspace` (42 pass), `cargo clippy --workspace --all-targets -- -D warnings` (clean), `cargo fmt --all --check` (clean). No `unwrap`/`panic` on non-test paths.

### Deps added
`rsa = "0.9"` (crypto dep), `rand = "0.8"` (dev-dep, test keygen), `base64` (schemes dep), `rsa`+`rand` (schemes dev-deps).

### Follow-up
B&N EPUB (TASK-10) reuses this same OCF + per-file-decrypt path; dispatch is already in place.
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
