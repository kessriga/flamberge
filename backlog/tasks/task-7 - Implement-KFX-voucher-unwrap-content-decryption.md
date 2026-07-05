---
id: TASK-7
title: Implement KFX voucher unwrap + content decryption
status: Done
assignee:
  - Kessriga Jeükal
created_date: '2026-07-03 19:56'
updated_date: '2026-07-05 15:25'
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
- [x] #1 KFX-ZIP members are located by magic; DRMION payload is stripped of the 8-byte prefix/suffix and the voucher member is identified by ProtectedData
- [x] #2 PID is split across the documented length combinations and the voucher KEK is derived via obfuscate + HMAC-SHA256; OBFUSCATION_TABLE is ported byte-for-byte and covered by a test
- [x] #3 Voucher AES-256-CBC unwrap + PKCS#7 yields the KeySet, and the 16-byte AES/RAW content key is extracted
- [x] #4 Encrypted pages are AES-128-CBC decrypted with per-page IV; Compressed pages are LZMA-alone decompressed after stripping the 0x00 filter byte
- [x] #5 A wrong PID fails the PKCS#7 padding check and the next candidate is tried; output is a repackaged zip
- [x] #6 Unit/integration test exercises the voucher key chain against known vectors or a synthesized voucher
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
## Plan

Vertical slice: KFX-ZIP container + voucher unwrap + content decrypt, ported from `ion.py` (DrmIon/DrmIonVoucher) and `kfxdedrm.py`. Spec §3.

### Dependencies
- Add `lzma-rs = "0.3"` to workspace deps + `flamberge-schemes` (LZMA "alone"/legacy `.lzma` via `lzma_rs::lzma_decompress`). `zip` v2 already present (use `raw_copy_file` + `start_file` to repackage).

### flamberge-formats::kfx_zip (container only, no crypto)
- `KfxZip::parse(&[u8])`: open zip, scan every member by **leading magic** — DRMION (`EA 44 52 4D 49 4F 4E EE`) → store `(name, payload[8..len-8])`; voucher (`E0 01 00 EA` BVM + contains ASCII `ProtectedData`) → store raw bytes. Fill the existing `drmion_members` / `voucher` fields.
- `repackage(original, &BTreeMap<name,bytes>)`: copy every member (`raw_copy_file`), substituting decrypted DRMION members (`start_file` + write). Returns new zip bytes.

### flamberge-schemes::kfx (the key chain)
- `obfuscate(secret, version)`: port byte-for-byte incl. `OBFUSCATION_TABLE` (38 entries, V1 identity; V9708 keeps the corrupted word bytes `..5c7d783034..`). Permute `index = i/rows + magic*(i%rows)`, XOR `sha256(word)[index%16]`.
- `DrmIonVoucher` port: parse VoucherEnvelope@<ver> (version, enc alg/transform/hash, lock_parameters, inner `voucher` BLOB → cipher_iv/cipher_text/license_type). `decryptvoucher`: build `shared="PIDv3"+alg+transform+hash` + sorted lock params (ACCOUNT_SECRET+secret / CLIENT_ID+dsn) → `obfuscate` → `kek=HMAC_SHA256(ss,"PIDv3")` → AES-256-CBC + pkcs7_unpad → parse KeySet→SecretKey(AES/RAW)→`encoded` 16-byte content key.
- `decrypt_voucher(env, pids)`: candidate list `[""] + keys.pids + keys.serials`; per PID pick the first matching split from `[(0,0),(16,0),(16,40),(32,40),(40,0),(40,40)]`; wrong PID → pkcs7 error → next.
- `DrmIon` port: parse doctype symbol + Envelope@1.0/2.0 list; per member: EnvelopeMetadata (encryption_voucher name), EncryptedPage (cipher_text/cipher_iv, nested Compressed@1.0 flag) → AES-128-CBC(content_key[..16], iv[..16]) + pkcs7 + optional LZMA-alone (strip 0x00 filter byte), PlainText (data, no decrypt). Concatenate pages.
- `decrypt(input, keys)`: not PK → NotThisScheme; parse zip; no DRMION member → NotThisScheme; unwrap voucher (license must be "Purchase"); decrypt each DRMION member; repackage; return `DecryptedBook{ extension:"kfx-zip" }`.

### Tests
- `obfuscate` vs Python vectors: v1 "hello"→identity; v2 "hello world"→`1a10684e99e09d75c36697dfb48f5b`; v3 16-byte→`5032ebbd55bd3023d591b9154adad481`; v28→`48c51f5e5442fbc3784303ab67dccc8f5ce34874`.
- OBFUSCATION_TABLE completeness (all 38 versions resolve).
- End-to-end voucher unwrap: synthesize a VoucherEnvelope (reuse the ion.rs test-encoder pattern) with a known content key, encrypt the KeySet, confirm the 16-byte key is recovered; wrong PID → next candidate.
- Content: synthesize EncryptedPage (plain + LZMA-compressed) → confirm round-trip decrypt.
- kfx_zip: build a zip with a DRMION + voucher member, confirm parse locates both and repackage substitutes.

### Verify
cargo fmt/build/clippy -D warnings/test on the workspace; update CLAUDE.md Status + Next-slice.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented the container in `flamberge-formats::kfx_zip` (scan members by leading magic, strip DRMION 8+8, repackage via `raw_copy_file`/`start_file`) and the full key chain in `flamberge-schemes::kfx` (obfuscate + OBFUSCATION_TABLE ported byte-for-byte from ion.py incl. V9708's corrupted word; DrmIonVoucher + DrmIon ports over the TASK-6 ION parser). Added `lzma-rs` for LZMA-alone page decompression and `zip` as a schemes dev-dependency for the e2e fixture. Added `SchemeError::NotPurchased`. `obfuscate` is checked against reference-Python vectors generated from ion.py; a full synthesized KFX-ZIP is decrypted end-to-end through `kfx::decrypt`. 88 workspace tests pass; fmt/clippy -D warnings clean. Note: architecture rule (formats do no crypto) meant DrmIon/DrmIonVoucher live in the scheme, not the ion module. `kdf.rs` was listed in the task's modified-files but needed no change — `hmac_sha256`/`pkcs7_unpad` already existed.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
## KFX voucher unwrap + content decryption (§3)

Implements the KFX-ZIP vertical slice end-to-end, ported from `ion.py` (`DrmIon`, `DrmIonVoucher`) and `kfxdedrm.py`.

### flamberge-formats::kfx_zip
- `KfxZip::parse`: scans zip members by **leading magic** — DRMION content (`\xeaDRMION\xee`, payload = `member[8..len-8]`) and the first ION member containing `ProtectedData` (the voucher).
- `repackage`: rebuilds the archive, substituting decrypted DRMION members and `raw_copy_file`-ing the rest.

### flamberge-schemes::kfx
- `obfuscate` + `OBFUSCATION_TABLE` ported byte-for-byte (38 versions; V1 identity; V9708 keeps the reference's corrupted word bytes so behavior matches exactly).
- Voucher chain: parse `VoucherEnvelope@<ver>` → build `shared = "PIDv3"+alg+transform+hash` + sorted lock params (ACCOUNT_SECRET/CLIENT_ID) → `obfuscate` → `kek = HMAC_SHA256(ss,"PIDv3")` → AES-256-CBC + PKCS#7 → extract 16-byte AES/RAW content key from the KeySet.
- PID handling: candidates are `"" + pids + serials`; each PID takes the first matching split of `[(0,0),(16,0),(16,40),(32,40),(40,0),(40,40)]`; a wrong PID fails PKCS#7 and the next is tried.
- Content: `DrmIon` port decrypts `EncryptedPage`s with AES-128-CBC (content_key[..16], per-page iv[..16]) + PKCS#7, LZMA-alone-decompresses `Compressed` pages after stripping the `0x00` UseFilter byte, and copies `PlainText`. Output is repackaged into a `.kfx-zip`.
- License gate: non-"Purchase" vouchers return `SchemeError::NotPurchased`.

### Dependencies / API
- Added `lzma-rs` (FORMAT_ALONE) to the workspace + schemes; `zip` as a schemes dev-dependency; new `SchemeError::NotPurchased` variant.

### Tests (16 new)
- `obfuscate` vs reference-Python vectors (v1/v2/v3/v28) + full-table coverage.
- Voucher unwrap round-trip (v1 identity + v2 obfuscated); wrong-secret rejection; candidate loop tries PIDs until one works and fails cleanly when exhausted.
- Plain + LZMA-compressed page decryption; PlainText copy.
- Full end-to-end: synthesize a KFX-ZIP (voucher + DRMION members), decrypt via `kfx::decrypt` with only a PID string, verify the rebuilt zip contains the decrypted page and copied members.

Verified: `cargo fmt --check`, `cargo clippy --workspace --all-targets -D warnings`, `cargo test --workspace` (88 pass). CLI already routes `.kfx-zip` through the KFX scheme (Mobi/Topaz fall through with `NotThisScheme`).

### Out of scope / follow-ups
- KDF SQLite (`CONT`) → KFX-ZIP unpacking (lives in the external KFX Input plugin). This path ingests `.kfx-zip` only.
- Next slice: OCF/EPUB container (TASK-8).
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
