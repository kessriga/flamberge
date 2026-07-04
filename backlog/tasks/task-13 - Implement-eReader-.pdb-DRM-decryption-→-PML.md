---
id: TASK-13
title: Implement eReader (.pdb) DRM decryption → PML
status: Done
assignee:
  - Kessriga Jeükal
created_date: '2026-07-03 19:59'
updated_date: '2026-07-04 11:01'
labels:
  - schemes
  - ereader
milestone: m-3
dependencies: []
references:
  - docs/DEDRM_SCHEMES.md
  - ../../external/DeDRM_tools/DeDRM_plugin/erdr2pml.py
modified_files:
  - crates/flamberge-crypto/src/des.rs
  - crates/flamberge-formats/src/lib.rs
  - crates/flamberge-formats/src/pmlz.rs
  - crates/flamberge-schemes/src/lib.rs
  - crates/flamberge-schemes/src/ereader/mod.rs
  - crates/flamberge-schemes/src/ereader/header.rs
  - crates/flamberge-schemes/src/ereader/content.rs
  - crates/flamberge-schemes/src/ereader/tests.rs
  - CLAUDE.md
priority: low
ordinal: 13000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement flamberge-schemes::ereader using the PalmDB parser (flamberge-formats::palmdb) and the DES helpers already in flamberge-crypto (ecb_decrypt, fix_key), plus the user-key generator in flamberge-keys::ereader.

Flow (§8): validate record-0 version (259/260/272); parse record 1 (DES key = first 8 bytes via fix_key), decrypt last 8 bytes to get cookie_shuf/cookie_size (range-checked), decrypt the last cookie_size bytes, and unshuffle. Read the version-dependent encrypted-key + SHA-1 offsets from the header, recover content_key = DES(fix_key(user_key), encrypted_key), and validate SHA1(content_key)==stored digest. Decrypt text records (records 1..num_text_pages) via zlib(DES(fix_key(content_key), record)); handle footnotes/sidebars (v272) with the XOR table. Emit PML (+ images) as a .pmlz (ZIP_STORED), with cp1252 high-byte escaping. Original: erdr2pml.py.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Record-0 version gate (259/260/272) and record-1 cookie decrypt + unshuffle produce a valid header with in-range cookie_shuf/cookie_size
- [x] #2 content_key = DES(fix_key(user_key), encrypted_key) is validated against the stored SHA-1; wrong name/CC is rejected clearly
- [x] #3 Text records decrypt via zlib(DES(fix_key(content_key), record)); v272 footnotes/sidebars handled via the XOR table
- [x] #4 Output is a .pmlz (stored) with images extracted and cp1252 high bytes escaped to \a###
- [x] #5 Integration test decrypts a synthesized eReader .pdb using a key from flamberge-keys::ereader and asserts PML content
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Autonomous execution: user pre-approved "implement the next task"; recording plan and proceeding.

## Module layout (module-per-concern, per CLAUDE.md)
- **flamberge-formats::pmlz** (new): `write(pml_name, pml_bytes, images) -> Vec<u8>` — a `ZIP_STORED` archive with `<name>.pml` at root + `images/<name>` entries. Container serialization → lives in formats (mirrors `ocf::repackage`), keeps `zip` out of schemes prod deps.
- **flamberge-schemes::ereader** → convert stub file into a module dir:
  - `header.rs`: `Header` struct + `parse(record0, record1, is_book)`. Key-INDEPENDENT: DES key = record1[0:8] (fixKey), decrypt last 8 → (cookie_shuf 3..0x14, cookie_size 0xf0..0x200), decrypt last cookie_size, `unshuff(input[..len-8], cookie_shuf)` → header `r`. Extract sub_version, num_text_pages(=r[2:4]-1), first/num image pages, flags (require 0x680), and version-dependent encrypted_key([8])/encrypted_key_sha([20]) offsets (259/260-sub13/260-sub11/272). For v272 also footnote/sidebar first+count and the xortable (sliced from raw record1 `data`, not `r`).
  - `content.rs`: `de_xor`, `clean_pml` (bytes >=0x80 -> `\aNNN` decimal), `extract_images`, `extract_pml` (text pages 1..=num_text_pages via `zlib(DES(fixKey(content_key), rec))`; v272 footnotes/sidebars via deXOR'd id table).
  - `mod.rs`: `detect` (PNRdPPrs/PDctPPrs) + `decrypt`: parse PalmDB, gate type_creator (else NotThisScheme), parse Header once, trial each `keys.ereader_keys`: `content_key = DES(fixKey(user_key), encrypted_key)`, accept when `sha1(content_key)==sha`; extract → clean → pmlz. Empty/failed keys -> NoKeyWorked.

## Output
`DecryptedBook { data: pmlz, extension: "pmlz", title: sanitized PalmDB name }`.

## Tests (TDD)
- crypto/keys already tested. New: header parse on synthesized v260 record set; `de_xor` vector; `clean_pml` high-byte escaping; pmlz writer round-trip (formats). Integration: synthesize a v260 `.pdb` (cookie + shuffled header + zlib text record) with a key from `flamberge_keys::ereader::user_key`, decrypt through top-level `decrypt(_, "pdb", _)`, assert PML text + image extraction; a v272 case exercising footnotes/deXOR; wrong-key -> NoKeyWorked; non-eReader PalmDB -> NotThisScheme.
<!-- SECTION:PLAN:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Implemented the eReader `.pdb` → PML decrypt path (§8), on branch `feat/task-13-ereader`.

**crypto/des:** added `ecb_encrypt` (the round-trip partner of `ecb_decrypt`), completing the cipher-pairing convention and enabling `.pdb` fixture construction. Round-trip + unaligned-input tests.

**formats/pmlz (new):** `pmlz::write(pml_name, pml, images)` builds the output container — a `ZIP_STORED` archive with `<name>.pml` at the root and an `images/<name>` folder. Container serialization lives in formats (mirrors `ocf::repackage`), keeping `zip` out of the schemes crate's production deps.

**schemes/ereader (stub → module dir):**
- `header.rs` — key-independent DRM header parse: DES key = record-1's own first 8 bytes (`fix_key`), decrypt its last 8 bytes → `(cookie_shuf 3..0x14, cookie_size 0xf0..0x200)`, decrypt the last `cookie_size` bytes, `unshuff` (scatter permutation) the remainder into the header `r`; require flags `0x680`; select version-dependent `encrypted_key`/`encrypted_key_sha` offsets (259 / 260-sub13 / 260-sub11 / 272); slice the v272 XOR table from the raw record-1 bytes.
- `content.rs` — `de_xor`, `clean_pml` (bytes ≥ 0x80 → `\aNNN` decimal), image extraction (32-byte cp1252 name at +4, data at +62), and `extract_pml` (text pages `1..=num_text_pages` via `zlib(DES(fix_key(content_key), record))`; v272 footnotes/sidebars emitted as `<footnote/>`/`<sidebar/>` blocks with ids recovered through the XOR table).
- `mod.rs` — `detect` (PNRdPPrs/PDctPPrs) + `decrypt`: parse the PDB, reject non-eReader containers with `NotThisScheme`, parse the header once, trial each `keys.ereader_keys` (`content_key = DES(fix_key(user_key), encrypted_key)`, accepted when `SHA1(content_key)` matches), then extract → clean → package a `.pmlz`. Empty/failed keys → `NoKeyWorked`.

Output: `DecryptedBook { extension: "pmlz", title: <sanitized PDB name> }`.

**Out of scope (documented):** dictionary index/sidebar pages beyond the standard sidebar path, and PML→HTML rendering (§5.5–5.6, matching the ADEPT/B&N precedent).

**Tests:** 10 new. Unit: DES round-trip, PMLZ writer, `de_xor` self-inverse + empty-table, `clean_pml` escaping. Integration through the top-level `decrypt(_, "pdb", _)`: a synthesized v260 book (2 text pages + image, key from `flamberge_keys::ereader::user_key`) asserting recovered PML with a cp1252 `é` escaped to `\a233` and the extracted image; a v272 book exercising the footnote + sidebar XOR path; wrong-key and no-key → `NoKeyWorked`; a non-eReader PalmDB → `NotThisScheme`. The v260 test pins the derived user key to the exact hex `flamberge keys ereader` prints, locking the CLI↔library interlock. Also verified end-to-end against the real `flamberge` binary (`keys ereader` → `decrypt --ereader-key` → inspected the `.pmlz`). Workspace fmt / clippy -D warnings / 158 tests all green.

CLAUDE.md Status updated (eReader now real; `pmlz` writer + DES `ecb_encrypt` noted; next slice = Kobo/TASK-14). This branch also carries a one-commit bookkeeping fix marking TASK-12 Done (its status/final-summary edit was left uncommitted and missed PR #13).
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
