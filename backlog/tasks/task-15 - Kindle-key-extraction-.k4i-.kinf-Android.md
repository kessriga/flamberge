---
id: TASK-15
title: Kindle key extraction (.k4i / .kinf / Android)
status: In Progress
assignee:
  - Kessriga Jeükal
created_date: '2026-07-03 19:59'
updated_date: '2026-07-04 15:41'
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

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
## Approach

Convert `flamberge-keys/src/kindle.rs` → a `kindle/` module dir (module-per-concern), and wire DB-derived PIDs into the Kindle schemes. Faithful port of `kindlekey.py` + `androidkindlekey.py` (spec §6).

### Module layout (`crates/flamberge-keys/src/kindle/`)
- `obfuscation.rs` — `decode`, `primes`, char-map tables (shared CHARMAP1/TESTMAP8; per-platform CHARMAP5/CHARMAP2 for PC vs Mac). Reuse `pid::{encode, encode_hash}` (identical). `Platform { Pc, Mac }` enum exposing `charmap5()`/`charmap2()`.
- `kinf.rs` — `.kinf` container: split on `/`, decode+unprotect header (PBKDF2 `header_key_data`/`HEADER.2011` iter 0x80 len 0x100 → AES-256-CBC), parse `[Version][Build][Cksum][Guid]`, per-record rotation de-obfuscation (`noffset = len - largest_prime(len/3)`), then value decrypt by version:
  - v5 Mac (emulated DPAPI): passwd=`encode(sha256(user+"+@#$%+"+id), charMap2)`, salt=`str(0x2df*build)+guid`, PBKDF2 iter 0x800 len 0x400 → AES-256-CBC → `decode(charMap2)`.
  - v6 (PC & Mac): key=`PBKDF2(encode(sha256(user+"+@#$%+"+id), charMap5), str(0x6d8*build)+guid, 10000, 0x400)[:32]`; value=AES-256 GCM-as-CTR (iv=`ct[:12]+00000002`, ignore tag) → `decode(charMap5)`.
  - v5 PC (Windows DPAPI): feature-gate `windows-dpapi`; off-Windows return `KeyError::Unsupported`.
  Public: `decrypt_kinf(data, platform, user, id_string)` + `decrypt_kinf_candidates(data, platform, user, &[id_strings])` (try until `DB.len()>6`). Values stored hex-encoded (k4i convention).
- `k4i.rs` — `load_k4i`: parse the `.k4i` JSON (flat name→hex map) via `serde_json`.
- `android.rs` — `serials_from_android(path)` dispatch by basename: `backup.ab` (strip 24-byte `ANDROID BACKUP` header → zlib inflate → tar → recurse into the two inner files), `AmazonSecureStorage.xml` (V1 AES-128-ECB key `0176…3523` / V2 DES-CBC from `md5^503("Thomsun was here!"+salt)`; obfuscated keys+values, PKCS pad), `map_data_storage.db` (SQLite `device_data`/`userdata` queries). Serials = dsn + tokens + dsn+token.
- `mod.rs` — re-exports + `KindleDb` + `extract_local_keys` (best-effort macOS gatherer: `$USER` + IDStrings via ioreg/MAC-munge; returns `Unsupported` off-macOS/Windows).
- `tests.rs`.

### AC4 wiring (schemes crate)
- Add `kindle_dbs: Vec<KindleDb>` to `KeyStore`.
- Port `getK4Pids` → `pid::k4_pids(rec209, token, &KindleDb) -> Vec<String>` (DSN from `DSN` key, or derive from `MazamaRandomNumber`+IDString/SerialNumber+UserName/UsernameHash; book PID + 2 variants + devicePID via CRC32 table).
- Call it in `mobipocket::normalize_pids`, `topaz::candidate_pids`, `kfx::candidate_pids`. Android serials already flow via `keys.serials`.

### Deps to add (flamberge-keys)
`flate2`, `tar`, `rusqlite` (bundled), `serde_json`. Add `tar` + `serde_json` to workspace deps.

### Tests (AC5)
encode/decode round-trip; `primes`/largest-prime + rotation invert; v6 value decrypt with a *synthesized* `.kinf` record (build the framing, encrypt with the v6 algo, decrypt, assert); v5 Mac synthesized record; android V1/V2 obfuscation round-trip; k4i JSON load; `k4_pids` shape.

### Commits (atomic)
1. obfuscation primitives + tests
2. kinf parsing (v5-mac + v6) + tests
3. k4i load
4. android serials
5. AC4 wiring (KeyStore + pid::k4_pids + schemes)
6. CLAUDE.md + finalize

### Scope notes
Windows v5 DPAPI + live Windows/macOS machine-value gathering are inherently host-specific (per gotchas); the offline crypto core is what's tested. eInk serial→PID (§6.5) already exists in `pid.rs`.
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
