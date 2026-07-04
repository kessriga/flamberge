---
id: TASK-10
title: Implement Barnes & Noble EPUB decryption
status: Done
assignee:
  - Kessriga Jeükal
created_date: '2026-07-03 19:57'
updated_date: '2026-07-04 08:49'
labels:
  - schemes
  - epub
  - ignoble
milestone: m-2
dependencies:
  - TASK-8
references:
  - docs/DEDRM_SCHEMES.md
  - ../../external/DeDRM_tools/DeDRM_plugin/ignobleepub.py
modified_files:
  - crates/flamberge-schemes/src/ignoble.rs
  - crates/flamberge-schemes/src/epub_common.rs
  - crates/flamberge-schemes/src/adept.rs
  - crates/flamberge-schemes/src/lib.rs
  - CLAUDE.md
priority: medium
ordinal: 10000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement flamberge-schemes::ignoble::decrypt_epub on the OCF layer (task-8), using the existing B&N keygen (flamberge-keys::ignoble).

Flow (§4.4): user key = base64-decode the 28-char ccHash, take first 16 bytes. AES-128-CBC decrypt the 64-char (48-byte) wrapped key from rights.xml with a zero IV, strip PKCS#7, take the last 16 bytes as the book key. For each encrypted file: AES-128-CBC decrypt with the book key (zero IV), drop the first 16 bytes, strip PKCS#7, raw-inflate (windowBits -15). Repackage via the OCF writer. Original: ignobleepub.py.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 User key first-16-bytes unwraps the rights.xml key via AES-128-CBC (zero IV) + PKCS#7 strip, taking the last 16 bytes as book key
- [x] #2 Encrypted files decrypt with the book key (zero IV), drop first 16 bytes, PKCS#7 strip, then raw inflate
- [x] #3 Output repackaged via the OCF writer; non-B&N EPUBs reported as not-this-scheme
- [x] #4 Integration test decrypts a synthesized B&N EPUB using a key from flamberge-keys::ignoble and asserts content
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Approach: B&N EPUB mirrors ADEPT EPUB on the same OCF layer; only the book-key unwrap differs (AES-CBC with user_key[:16] vs RSA). The per-file member decrypt is byte-identical to ADEPT's (spec's "decrypt whole, zero IV, drop first 16 plaintext bytes" == ADEPT's "IV = first ciphertext block, decrypt remainder"), so share it.

Steps:
1. Refactor (safe, guarded by existing adept tests): extract the shared per-file EPUB helpers out of adept.rs into a new `epub_common` module in flamberge-schemes — `decrypt_member` (drop-16 + PKCS#7 strip + raw inflate), `raw_inflate`, `decode_b64` (whitespace-tolerant base64), and the `invalid()` FormatError helper. Point adept.rs at them; confirm adept tests stay green.
2. TDD ignoble::decrypt_epub:
   - unwrap_book_key(cchash_b64, wrapped): base64-decode the 28-char ccHash, take first 16 bytes as user key; AES-128-CBC decrypt the 48-byte wrapped key with a zero IV; strip PKCS#7; book key = last 16 bytes. Invalid PKCS#7 => Ok(None) (wrong-key signal, the B&N analog of ADEPT's [-17] check, used to select among candidate bandn_keys).
   - recover_book_key: try each keys.bandn_keys, first that validates wins; else NoKeyWorked.
   - decrypt_epub: keep the existing detection guard (NotThisScheme unless scheme()==BarnesNoble), unwrap the rights.xml key, decrypt each encryption.xml-listed member via epub_common::decrypt_member, repackage via ocf::repackage.
3. Tests: unit tests for unwrap (right key, wrong key => None), plus an end-to-end that synthesizes a B&N EPUB whose user key comes from flamberge_keys::ignoble::generate_key (AC#4), routed through crate::decrypt("epub") to prove IgnobleEpub claims it before ADEPT. Also: wrong key => NoKeyWorked, ADEPT-shaped (172-char) falls through to NotThisScheme, plain/non-zip => NotThisScheme.
4. Verify build/test/clippy/fmt; update CLAUDE.md Status section (ignoble EPUB now real).
<!-- SECTION:PLAN:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Implemented Barnes & Noble ("ignoble") EPUB decryption end-to-end on the existing OCF layer (§4.4), completing the last non-PDF ADEPT/B&N slice.

**What changed**
- New `flamberge-schemes::epub_common` module holds the per-file member decrypt (`decrypt_member`: AES-128-CBC with IV = first 16 ciphertext bytes ≡ "decrypt whole/zero-IV then drop first 16 plaintext bytes", PKCS#7 strip, raw inflate), `raw_inflate`, whitespace-tolerant `decode_b64`, and the `invalid()` helper — extracted from `adept.rs` (safe refactor, guarded by existing ADEPT tests).
- `ignoble::decrypt_epub` implemented: base64-decode the 28-char ccHash user key → first 16 bytes; AES-128-CBC unwrap the 64-char (48-byte) `rights.xml` key with a zero IV; strip PKCS#7; book key = last 16 bytes. `recover_book_key` tries each `KeyStore::bandn_keys`, selecting the correct one by PKCS#7 validity (the B&N analog of ADEPT's `[-17]==0x00` check), else `NoKeyWorked`. Each encrypted member decrypts via the shared `epub_common::decrypt_member`; repackaged with `ocf::repackage`. Non-B&N containers (172-char ADEPT key, DRM-free, non-zip) return `NotThisScheme` so `.epub` dispatch falls through to ADEPT.

**Key insight**: B&N and ADEPT per-file decryption are the same operation — CBC block i is D(Cᵢ)⊕Cᵢ₋₁, so "zero-IV decrypt then drop block 0" equals "use block 0 as IV, decrypt the rest". One shared `decrypt_member` serves both.

**Tests** (8 new, all green): unit unwrap right-key/wrong-key(=>None); end-to-end through `crate::decrypt("epub")` with a user key generated by `flamberge_keys::ignoble::generate_key` (AC#4), asserting IgnobleEpub claims the book before ADEPT and content round-trips (deflated + stored members, DRM META dropped, mimetype preserved); wrong-key and no-key => NoKeyWorked; ADEPT-shaped / plain-zip / non-zip => NotThisScheme.

**Verification**: `cargo build`, `cargo test --workspace` (schemes 50 tests, all crates pass), `cargo clippy --workspace --all-targets -D warnings`, and `cargo fmt --all -- --check` all clean. No panic/unwrap/expect on non-test paths.

Note: B&N *PDF* (§4.5, EBX_HANDLER/RC4) remains stubbed pending the PDF tokenizer (TASK-11/12). CLI key-subcommand wiring for B&N keys is TASK-18; the scheme + dispatch are wired now.
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
