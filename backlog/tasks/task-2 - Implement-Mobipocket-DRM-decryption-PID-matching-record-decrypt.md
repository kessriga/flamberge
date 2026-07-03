---
id: TASK-2
title: Implement Mobipocket DRM decryption (PID matching + record decrypt)
status: To Do
assignee: []
created_date: '2026-07-03 19:54'
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

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 cargo build succeeds with no warnings
- [ ] #2 cargo test passes (unit and integration)
- [ ] #3 cargo clippy passes with no warnings
- [ ] #4 no panic!/unwrap/expect on non-test code paths
- [ ] #5 behavior matches docs/DEDRM_SCHEMES.md and code cites the relevant section
- [ ] #6 public items have doc comments
<!-- DOD:END -->
