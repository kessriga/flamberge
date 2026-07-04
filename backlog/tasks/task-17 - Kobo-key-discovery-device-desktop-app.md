---
id: TASK-17
title: Kobo key discovery (device + desktop app)
status: Done
assignee:
  - Kessriga Jeükal
created_date: '2026-07-03 20:00'
updated_date: '2026-07-04 18:54'
labels:
  - keys
  - kobo
milestone: m-4
dependencies: []
references:
  - docs/DEDRM_SCHEMES.md
  - ../../external/DeDRM_tools/Obok_plugin/obok/obok.py
modified_files:
  - crates/flamberge-keys/src/kobo/mod.rs
  - crates/flamberge-keys/src/kobo/db.rs
  - crates/flamberge-keys/src/kobo/host.rs
  - crates/flamberge-cli/src/main.rs
  - CLAUDE.md
priority: low
ordinal: 17000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement flamberge-keys::kobo::discover_userkeys: locate the Kobo library DB (device `.kobo/KoboReader.sqlite` or desktop `Kobo.sqlite` per-OS), read `UserID`s from the `user` table, enumerate host MAC addresses and the device serial (from `.adobe-digital-editions/device.xml`), then feed them into the already-implemented derive_userkeys to produce candidate 16-byte keys. Handle the SQLite WAL header workaround. Return keys into KeyStore.kobo_keys. Spec: docs/DEDRM_SCHEMES.md §9.1–9.2. Original: obok.py (KoboLibrary).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Locates the Kobo DB on the current OS (device and desktop paths) and reads UserIDs
- [x] #2 Enumerates host MAC addresses and, when present, the device serial from device.xml
- [x] #3 Feeds inputs into derive_userkeys and returns candidate keys into KeyStore.kobo_keys
- [x] #4 Missing DB / no inputs returns a clear NotFound error rather than a panic
- [x] #5 Unit test drives derive inputs from a fixture DB and asserts a non-empty candidate set
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
## Approach

Refactor `crates/flamberge-keys/src/kobo.rs` into a `kobo/` module dir (module-per-concern, mirroring `adobe/` and `schemes::kobo`):

- **`kobo/mod.rs`** — public API. Keeps `KOBO_HASH_KEYS` + `derive_userkeys` (unchanged). `discover_userkeys()` orchestrates: locate DB → read UserIDs → enumerate MACs + device serial → `derive_userkeys`. Returns `NotFound` when the DB is missing or no MAC/UserID inputs exist (AC#4).
- **`kobo/db.rs`** — `read_userids(db_bytes) -> Result<Vec<String>>`: WAL-patch a temp copy (bytes 18–19 → `01 01`, same trick as `schemes::kobo::db`, duplicated because `keys` cannot depend on `schemes`), open read-only, `SELECT UserID FROM user`. Pure over bytes → testable with a fixture DB (AC#1 read, AC#5).
- **`kobo/host.rs`** — on-host glue: `find_kobo_db()` resolves the desktop-app DB per-OS (macOS `~/Library/Application Support/Kobo/Kobo Desktop Edition/Kobo.sqlite`, Windows `%LOCALAPPDATA%\Kobo\Kobo Desktop Edition\Kobo.sqlite`) and, when a mounted device root is found, its `.kobo/KoboReader.sqlite`; `enumerate_macaddrs()` shells out per-OS (`ifconfig`/`ip`/`getmac`) with a **pure** `parse_macaddrs(text)` scanner (AC#2, testable); `device_serial(root)` reads `.adobe-digital-editions/device.xml` via a **pure** `parse_device_serial(xml)` (AC#2, testable).

## Testing
- `read_userids` against a fixture SQLite built in-test (temp file with a `user` table) → asserts UserIDs read.
- `parse_macaddrs` on sample `ifconfig`/`ip` output → asserts uppercase colon-form MACs extracted.
- `parse_device_serial` on a sample `device.xml` → asserts the `deviceSerial` text.
- End-to-end derive: fixture UserIDs + a fixed MAC → `derive_userkeys` non-empty (AC#5).

## CLI
Wire `keys kobo` (currently `bail!`) to `discover_userkeys()`, printing hex keys + a count to stderr, mirroring `keys adobe`.

## Out of scope
Live device auto-mount scanning (obok takes an explicit device path; we probe the desktop path + honor a found device root). Linux full-filesystem walk for `Kobo.sqlite` (obok's fallback) — return `NotFound` instead.

Reference: docs/DEDRM_SCHEMES.md §9.1–9.2; obok.py `KoboLibrary.__init__`/`__getmacaddrs`/`__getuserids`/`__getuserkeys`.
<!-- SECTION:PLAN:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Implemented `flamberge-keys::kobo::discover_userkeys` (§9.1–9.2), the on-host input-gathering feeding the existing `derive_userkeys`. Refactored `kobo.rs` into a `kobo/` module dir:

- **`db.rs`** — `read_userids`: WAL-patch a temp DB copy (bytes 18–19 → `01 01`), open read-only, `SELECT UserID FROM user` (skipping NULL/empty). Duplicates the WAL trick from `schemes::kobo::db` because `keys` can't depend on `schemes`.
- **`host.rs`** — `find_kobo_db` scans mount roots (`/Volumes`, `/media/$USER`, `/run/media/$USER`, `/mnt`, Windows drive letters) for a device `.kobo/KoboReader.sqlite`, else the per-OS desktop-app `Kobo.sqlite`; `enumerate_macaddrs` shells `ifconfig`/`ip`/`getmac`; `device_serial` reads the mounted device's `device.xml`. OS glue is thin; the parsing (`parse_macaddrs`, `parse_device_serial`) is pure + unit-tested.
- **`mod.rs`** — orchestration; `NotFound` (never panics) on missing DB / no UserIDs / no MACs.
- CLI `keys kobo` wired (was `bail!`).

Verification: 11 kobo unit tests + full workspace suite (219 tests) pass; fmt/clippy clean; drove `keys kobo` on a Kobo-less host → clean `NotFound`, exit 1, no panic. All ACs + DoD met. CLAUDE.md status updated (Kobo discovery moved from stubbed to real). PR: https://github.com/kessriga/flamberge/pull/18

Out of scope (documented): Linux full-filesystem walk for `Kobo.sqlite` (obok's last-resort fallback).
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
