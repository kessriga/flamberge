---
id: TASK-2
title: Implement Mobipocket DRM decryption (PID matching + record decrypt)
status: In Progress
assignee:
  - kessriga.jeukal@proton.me
created_date: '2026-07-03 19:54'
updated_date: '2026-07-03 20:24'
labels:
  - schemes
  - kindle
  - mobipocket
milestone: m-0
dependencies:
  - TASK-1
references:
  - docs/DEDRM_SCHEMES.md
  - ../../external/DeDRM_tools/DeDRM_plugin/mobidedrm.py
  - ../../external/DeDRM_tools/DeDRM_plugin/kgenpids.py
modified_files:
  - crates/dedrm-schemes/src/mobipocket.rs
  - crates/dedrm-keys/src/pid.rs
priority: high
ordinal: 2000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement the full Mobipocket decrypt path in dedrm-schemes::mobipocket, composing the MOBI header parser (task-1, provides record-0 fields, the DRM block, and rec209/token) with the existing PC1 cipher (dedrm-crypto::pc1) and PID helpers (dedrm-keys::pid).

Type-2 flow: for each candidate PID, `temp_key = PC1::encrypt(KEYVEC1, pid.pad16)`, checksum-filter vouchers on byte 0x0C, `PC1::decrypt(temp_key, cookie)`, accept when verification==ver and (flags & 0x1F)==1; recover the 16-byte finalkey; PID-less fallback with KEYVEC1. Type-1 flow: PC1-decrypt the stored book key with T1_KEYVEC. Then decrypt text records 1..=records, stripping trailing-data bytes (getSizeOfTrailingDataEntries) before PC1 and re-appending them. Also expand candidate PIDs from serials/rec209/token (complete dedrm-keys::pid getKindlePids/getK4Pids variants as needed) and normalize 10-char PIDs to 8.

Spec: docs/DEDRM_SCHEMES.md §2.3–2.5. Original: mobidedrm.py (parseDRM, processBook), kgenpids.py.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Type-2 voucher matching recovers the correct finalkey for a matching PID and falls back to the PID-less path when no PID matches
- [ ] #2 Type-1 books decrypt via T1_KEYVEC; unencrypted (type 0) books pass through, including Print Replica detection
- [ ] #3 Text records are PC1-decrypted with trailing-data bytes correctly stripped and re-appended; section 0 and tail sections are untouched
- [ ] #4 Candidate PID list is assembled from explicit PIDs and serials (rec209/token) and 10-char PIDs are normalized to 8
- [ ] #5 Rental/expiry (EXTH 406 nonzero) is rejected with a clear error
- [ ] #6 Unit tests cover voucher matching with synthetic vouchers and a full-record decrypt against a known key/PID
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
## Plan (docs/DEDRM_SCHEMES.md §2.3–2.5; mobidedrm.py processBook/parseDRM)

All logic lands in `crates/dedrm-schemes/src/mobipocket.rs`; PID helpers in `dedrm-keys::pid` already exist (`book_pid_from_serial`, `eink_pid_from_serial`). No new PID code expected.

### mobipocket::decrypt(input, keys)
1. `detect()` gate: `PalmDb::parse` + BOOKMOBI/TEXtREAd magic → else `NotThisScheme` (let Topaz/KFX try).
2. Parse `MobiHeader::from_image`. Read `encryption_type` (rec0 0x0C).
3. crypto_type 0 → pass-through: output = input unchanged, ext from print-replica(section1 %MOP)/mobi_version.
4. crypto_type not in {1,2} → `UnknownEncryption(t)`.
5. EXTH 406 (u64 BE) nonzero → `RentalBook`.
6. Assemble candidate PIDs: `keys.pids` + per serial in `keys.serials` → `book_pid_from_serial(serial, rec209, token)` and `eink_pid_from_serial(serial)`. Normalize: 10-char→take first 8 (checksum validated, warn-only); 8-char as-is; else skip.
7. type 1: bookkey_data = TEXtREAd→rec0[0x0E..+16], else rec0[mobi_length+16..+16]; `found_key = PC1::decrypt(T1_KEYVEC, bookkey_data)`; pid="00000000".
8. type 2: drm block from header; `drm_count==0` → `DrmNotInitialised`; `find_book_key(vouchers, count, goodpids)`:
   - per pid: `temp_key = PC1::encrypt(KEYVEC1, pid.pad16)`, `sum=Σtemp_key&0xFF`; scan 48-byte vouchers `>LLLBxxx32s`; on `cksum==sum` do `PC1::decrypt(temp_key, cookie)` → `>LL16sLL`; accept if `verification==ver && flags&0x1F==1` → finalkey.
   - PID-less fallback: `temp_key=KEYVEC1` raw, accept on `verification==ver` only.
   - none → `NoKeyWorked`.
9. Decrypt records 1..=text_record_count: `extra = getSizeOfTrailingDataEntries(rec, extra_data_flags)`; `PC1::decrypt(found_key, rec[..len-extra])`; write into output clone in place; trailing bytes untouched. Record 1 `%MOP` ⇒ print-replica.
10. Patch output record 0: zero DRM voucher block (drm_ptr..+drm_size, type 2 only); write 0xA8 = FF*4 + 00*12 (type 2); zero crypto type at 0x0C (both types). Section 0 header + tail sections (>records+1) untouched.
11. Extension: print_replica→azw4; mobi_version>=8→azw3; else mobi.

### Errors (add to SchemeError)
`RentalBook`, `UnknownEncryption(u16)`, `DrmNotInitialised`. Reuse `NoKeyWorked` for no-PID-matched.

### Tests (colocated)
- `getSizeOfTrailingDataEntries` varint cases.
- Voucher matching: synthetic voucher → recovers finalkey for matching PID; PID-less fallback path.
- Full round-trip: synth BOOKMOBI (rec0+voucher+encrypted text) decrypts to plaintext, record-0 patched.
- Type-1 T1_KEYVEC round-trip.
- Type-0 pass-through; print-replica → azw4.
- Rental (EXTH 406) rejected.
<!-- SECTION:PLAN:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 cargo build succeeds with no warnings
- [ ] #2 cargo test passes (unit and integration)
- [ ] #3 cargo clippy passes with no warnings
- [ ] #4 no panic!/unwrap/expect on non-test code paths
- [ ] #5 behavior matches docs/DEDRM_SCHEMES.md and code cites the relevant section
- [ ] #6 public items have doc comments
<!-- DOD:END -->
