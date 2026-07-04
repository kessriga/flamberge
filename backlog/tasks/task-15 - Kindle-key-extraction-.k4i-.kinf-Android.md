---
id: TASK-15
title: Kindle key extraction (.k4i / .kinf / Android)
status: Done
assignee:
  - Kessriga Jeükal
created_date: '2026-07-03 19:59'
updated_date: '2026-07-04 16:05'
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
  - Cargo.toml
  - crates/flamberge-crypto/src/des.rs
  - crates/flamberge-keys/Cargo.toml
  - crates/flamberge-keys/src/lib.rs
  - crates/flamberge-keys/src/pid.rs
  - crates/flamberge-keys/src/kindle/mod.rs
  - crates/flamberge-keys/src/kindle/obfuscation.rs
  - crates/flamberge-keys/src/kindle/kinf.rs
  - crates/flamberge-keys/src/kindle/k4i.rs
  - crates/flamberge-keys/src/kindle/android.rs
  - crates/flamberge-schemes/src/mobipocket.rs
  - crates/flamberge-schemes/src/topaz.rs
  - crates/flamberge-cli/src/main.rs
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
- [x] #1 .k4i JSON databases load into the KeyStore; .kinf record framing + symbol/rotation decode is implemented
- [x] #2 Offline .kinf paths (macOS v5 emulated DPAPI, v6 GCM-as-CTR) decrypt values; Windows v5 DPAPI is feature-gated and returns a clear Unsupported error when unavailable
- [x] #3 Android serials are extracted from backup.ab, AmazonSecureStorage.xml (V1/V2 obfuscation), and map_data_storage.db
- [x] #4 Extracted serials/DBs expand the candidate PID list used by the Kindle schemes
- [x] #5 Unit tests cover the symbol map encode/decode, prime rotation, and v6 value decryption with a synthesized record
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Deviations from plan: (1) colocated each submodule's tests beside it (per CLAUDE.md convention) rather than a separate tests.rs; (2) did not wire DB-derived PIDs into kfx::candidate_pids — KFX has no EXTH-209 record and unwraps its voucher via a DSN/secret split, so getK4Pids doesn't cleanly apply; Android-derived serials still reach KFX via keys.serials. (3) added tempfile to keys deps to materialize the tar-embedded SQLite DB for rusqlite.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Implemented `flamberge-keys::kindle` (spec §6), the offline Kindle key extraction, and wired the results into the Kindle schemes and CLI.

**What's real (offline, reproducible + tested):**
- `kindle/obfuscation.rs` — the shared `.kinf` anti-tamper layer: `decode` (inverse of `pid::encode`), `largest_prime`/`derotate` record rotation, and the per-platform 64-byte char maps (PC vs Mac) behind a `Platform` selector.
- `kindle/kinf.rs` — `.kinf2011`/`.kinf2018` container decryption (`decrypt_kinf` / `decrypt_kinf_candidates`): split `/`-joined records, decode+AES-unprotect the header for `[Version][Build][Guid]`, walk each key record (name hash → count → de-rotate → testMap8 decode), then decrypt by version — **macOS v5 emulated DPAPI** (PBKDF2 + AES-256-CBC) and **v6 GCM-as-CTR** on both platforms. Windows v5 DPAPI returns `KeyError::Unsupported`. Verified by synthesized-record round-trips for both offline versions.
- `kindle/k4i.rs` — `.k4i` JSON DB loader (flat name→hex map).
- `kindle/android.rs` — `serials_from_android`: `AmazonSecureStorage.xml` (V1 AES-128-ECB / V2 DES-CBC obfuscation on keys+values), `map_data_storage.db` (SQLite), and `backup.ab` (24-byte ANDROID BACKUP header → zlib → tar, recursing into the two inner files).

**AC4 wiring:** `pid::k4_pids` ports `getK4Pids` (DSN from an explicit key or reconstructed from MazamaRandomNumber+serial+username; device PID + primary + 2 variant book PIDs). New `KeyStore::kindle_dbs` feeds DB-derived PIDs into `mobipocket::normalize_pids` and `topaz::candidate_pids`; Android serials already flow via `keys.serials`.

**Supporting:** added `des::cbc_encrypt` (round-trip partner, needed by the V2 lookup); CLI `decrypt --k4i` / `--android` flags load keys into the store (smoke-tested end-to-end).

**Still stubbed (out of scope — host-specific):** `kindle::extract_local_keys` (gathering `$USER`/ioreg/volume-serial off the live machine) and Windows v5 real DPAPI. These need the user's actual OS profile and aren't reproducible offline.

**Verification:** `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` (196 tests) all green. New tests cover encode/decode + char maps, largest-prime/rotation, v6 and v5-Mac synthesized `.kinf` decryption, wrong-IDString failure + candidate selection, Windows-v5 Unsupported, k4i parsing, Android V1/V2 obfuscation + SQLite + backup.ab, `k4_pids` shapes, and a scheme-level test that a `kindle_db` expands the candidate PID list.

Commits: `f47b009` obfuscation · `370cd84` kinf v5/v6 · `77f805f` k4i · `769c402` des cbc_encrypt · `7185df5` android · `253c878` k4_pids + scheme wiring · `b7fa6c9` CLI flags · `d9b348b` CLAUDE.md.
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
