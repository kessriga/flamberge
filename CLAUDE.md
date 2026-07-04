# flamberge — Project Guide

Standalone Rust CLI that reimplements the **DeDRM_tools** Calibre plugins (ebook DRM removal).

## Sources of truth
- `docs/DEDRM_SCHEMES.md` — **the spec.** Byte-level reference for every scheme (offsets, constants, key derivation). **Read the relevant section before implementing any scheme.** Sections: §1 crypto, §2 Mobipocket, §3 KFX/ION, §4 B&N, §5 Topaz, §6 Kindle keys, §7 Adobe ADEPT, §8 eReader, §9 Kobo, §10 Rust guidance.
- `../../external/DeDRM_tools/DeDRM_plugin/` — the original Python source the spec was derived from; consult it when the spec is ambiguous.

## Working conventions
- Tasks live in **Backlog.md** (`backlog/tasks/`), not a Clavix `tasks.md`. Per task: mark In Progress, record a plan in the task, implement with tests, verify build/test/clippy/fmt, mark Done with a final summary.
- **You may create Backlog tasks on your own initiative** — e.g. to capture a review follow-up, split out discovered scope, or track a cleanup — without asking first. Prefer this over silently expanding a task's scope. (This overrides the generic Backlog-MCP guidance about not creating tasks unprompted.)
- **You may add dependencies to the project when a task genuinely needs one** (a workspace crate under `[workspace.dependencies]`, then referenced with `.workspace = true` in the crate's `Cargo.toml`). Favour well-maintained, widely-used crates; keep the dependency surface small and note why in the task/commit. No need to ask first.
- **When finishing a task, update this CLAUDE.md too** if the completed work changed anything documented here (e.g. the Status section, conventions, or gotchas). Skip only when there is genuinely nothing to update.
- **Commits: atomic and reasonably short** — one logical change per commit, your judgment on boundaries. Keep unrelated cleanups (e.g. lint fixes) in their own commits.
- **Separate concerns into separate modules whenever possible** — favour a module-per-concern layout (e.g. lexer / parser / object model / serializer each in their own file under a `foo/` module dir) over one large file. Scope internal items `pub(super)` and re-export only the genuine public API from `mod.rs`; keep each module's tests beside it.
- **One branch per task**, cut from `main` (e.g. `feat/task-4-topaz`); never commit to `main` directly. `main` is protected — integrate via PR only, with CI green and commits signed. Commit signing (SSH) is configured globally, so commits sign automatically.
  - **Before starting a task:** switch to `main`, pull, then create and switch to the task branch.
  - **After the task is done, before opening the PR:** pull `main` and rebase the task branch onto it.

## Layout & commands
- Cargo workspace under `crates/`; dependency direction: `flamberge-crypto` ← `flamberge-formats`, `flamberge-keys` ← `flamberge-schemes` ← `flamberge-cli` (binary name `flamberge`).
- `cargo build` / `cargo test` from repo root. Unit tests are colocated in each module; every cipher has a round-trip test. The workspace-level, cross-scheme end-to-end suite lives in the `flamberge-integration-tests` crate (`publish = false`): `src/fixtures/` synthesizes a DRM-encrypted book per scheme from the project's own crypto (fixtures are a `pub` lib, not `tests/common/`, to dodge the integration-test dead-code-warning footgun and because an external test crate can't see a scheme's `#[cfg(test)]` builders), and `tests/schemes.rs` decrypts each through `flamberge_schemes::decrypt` + asserts a wrong key fails cleanly.
- CI (`.github/workflows/ci.yml`) gates every PR: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and build+test on Linux/macOS/Windows. Run `cargo fmt` before committing — warnings and unformatted code fail the merge.
- Errors: `thiserror` in libs, `anyhow` in the CLI. Never `panic!`/`unwrap` on a real code path.

## Status (what's real vs stub)
- **Real + tested:** all of `flamberge-crypto` (PC1, Topaz, AES CBC/ECB/CTR, DES ECB+CBC with eReader `fix_key`, RC4, CRC-32, PBKDF2, PKCS#7, **RSA raw private-decrypt** `rsa::private_decrypt_raw` — textbook `c^d mod n` over a PKCS#1 `RSAPrivateKey` DER, OpenSSL `RSA_NO_PADDING` semantics; the ADEPT `[-17]==0x00` unwrap is applied by the caller); `flamberge-formats::palmdb`, `mobi` + `topaz_container` (TPZ0 header/payload/metadata parsing) + `ion` (Amazon ION binary pull parser: VarUInt/VarInt, type descriptors, list/struct navigation, symbol table with the `ProtectedData` shared import, annotation resolution) + `kfx_zip` (KFX-ZIP: locate DRMION/voucher members by magic, strip DRMION 8+8, repackage with decrypted members via `raw_copy_file`) + `ocf` (EPUB/OCF: parse `rights.xml`+`encryption.xml` for the wrapped-key base64 and encrypted-path set via namespace-aware quick-xml, detect ADEPT vs B&N by wrapped-key length 172/64, repackage `mimetype`-first+stored/rest-deflated dropping the DRM META files — I/O + XML only, crypto lives in the schemes) + `pmlz` (PMLZ writer: a `ZIP_STORED` archive with `<name>.pml` at the root + an `images/` folder — the eReader output container) + `pdf` (pdfminer-derived tokenizer + object model: lexer, recursive-descent parser with `n g R` refs, classic `xref` tables **and** PDF-1.5 xref streams, object streams (`ObjStm`), filters Flate/LZW/ASCII85 + PNG/TIFF predictors, lazy `PdfDocument::get_object`, `/Encrypt`+`/ID` exposed, a per-object decipher hook (`PdfDocument::set_decipher` — applies a scheme-supplied `Fn(objid,genno,bytes)` to uncompressed objects only, mirroring `ineptpdf.getobj`+`decipher_all`), and a `PdfSerializer` that re-emits a clean classic-xref PDF forcing gen 0 / dropping `/Encrypt` / dissolving ObjStm); `flamberge-keys` offline generators (`pid` incl. `k4_pids` = `getK4Pids`, `ignoble`, `ereader`, `kobo::derive_userkeys`) and **Kindle key extraction** (`kindle`, module dir `obfuscation`/`kinf`/`k4i`/`android`): loads `.k4i` JSON DBs, decrypts `.kinf2011`/`.kinf2018` via the offline paths (macOS v5 emulated DPAPI + v6 GCM-as-CTR — `decrypt_kinf`/`decrypt_kinf_candidates`; Windows v5 DPAPI returns `Unsupported`), and mines Android `backup.ab`/`AmazonSecureStorage.xml` (V1 AES-ECB / V2 DES-CBC) / `map_data_storage.db` for candidate serials (`serials_from_android`). A decoded DB in `KeyStore::kindle_dbs` expands the Mobipocket/Topaz PID search via `pid::k4_pids`; both are wired through the CLI (`decrypt --k4i` / `--android`). Still stubbed: `kindle::extract_local_keys` (host machine-value gathering — `$USER`/ioreg/volume-serial — is OS-specific). **Adobe ADEPT key extraction** (`adobe`, module dir `mod`/`macos`/`windows`): macOS `activation.dat` is fully real+tested — recursive locate under `~/Library/Application Support/Adobe/Digital Editions`, namespace-aware `adept:credentials/adept:privateLicenseKey` parse (`parse_activation_dat`), base64-decode, strip the 26-byte header, validate the PKCS#1 DER (`flamberge_crypto::rsa::private_key_modulus_len`); wired through the CLI (`keys adobe`). The portable Windows *algorithm* is implemented+tested (`pack_entropy` = the `>I12s3s13s` DPAPI entropy layout; `decrypt_private_license_key` = AES-128-CBC zero-IV + 26-byte/PKCS#7 strip), but live DPAPI/registry gathering returns `Unsupported` (not reproducible offline, same as the Kindle v5 path). **Kobo on-host key discovery** (`kobo::discover_userkeys`, module dir `mod`/`db`/`host`) is real: locate the library DB (scan `/Volumes` etc. for a mounted device `.kobo/KoboReader.sqlite`, else the per-OS desktop-app `Kobo.sqlite`), WAL-patch a temp copy and read `SELECT UserID FROM user` (`db::read_userids`), enumerate NIC MACs (shelling `ifconfig`/`ip`/`getmac`, pure `host::parse_macaddrs`) plus the mounted device's `device.xml` serial (pure `host::parse_device_serial`), then feed both into `derive_userkeys`; missing DB / no inputs yields `NotFound` (never panics); wired through the CLI (`keys kobo`). The **Mobipocket, Topaz, KFX, Adobe ADEPT EPUB+PDF, Barnes & Noble EPUB+PDF, eReader `.pdb`, and Kobo KEPUB schemes end-to-end** (`flamberge-schemes::mobipocket`, `topaz`, `kfx`, `adept::decrypt_epub`/`decrypt_pdf`, `ignoble::decrypt_epub`/`decrypt_pdf`, `ereader`, `kobo`, wired through the CLI). Topaz emits a repackaged decrypted `TPZ0` (extension `tpz`); KFX emits a repackaged `.kfx-zip` (voucher unwrap → AES-128-CBC page decrypt + LZMA-alone via `lzma-rs`); ADEPT emits a repackaged `.epub` (RSA-unwrap `rights.xml` book key → per-file AES-128-CBC → PKCS#7 strip → raw inflate); B&N emits a repackaged `.epub` (AES-128-CBC unwrap the 64-char `rights.xml` key with `user_key[:16]`/zero IV → book key = last 16 bytes → same per-file path). ADEPT and B&N share the per-file member decrypt (`schemes::epub_common::decrypt_member` — IV = first 16 ciphertext bytes ≡ "drop first 16 plaintext bytes" — plus `decode_b64`); stored members pass through. Both **PDF** schemes (`adept::decrypt_pdf`, `ignoble::decrypt_pdf`, extension `pdf`) share `schemes::pdf_common`: read the `/Encrypt` `EBX_HANDLER` `ADEPT_LICENSE` (base64 → raw inflate −15 → adept XML → `encryptedKey`), unwrap the book key via each scheme's existing `recover_book_key` (ADEPT RSA `[-17]==0` last-16 / B&N zero-IV AES + PKCS#7 last-16), then RC4 every object with an MD5 per-object key (`genkey_v2`/`v3`, version by `/Encrypt` `/V`) and re-serialize. Scheme discrimination is by wrapped-key length (B&N = 48-byte AES ciphertext, ADEPT = RSA modulus). The AES content branch (`Adobe.APS`/Standard-V4, `genkey_v4`) and the German Onleihe principal key are out of scope. eReader (`flamberge-schemes::ereader`, module dir `header`/`content`/`mod`) parses the Palm PDB, gates record-0 version (259/260/272), decrypts+unshuffles the record-1 cookie into the header (key-independent), unwraps `content_key = DES(fix_key(user_key), encrypted_key)` validated by `SHA1`, then per text record `zlib(DES(fix_key(content_key), record))`; v272 footnotes/sidebars are de-obfuscated through the header XOR table (`de_xor`), images are copied out, high bytes are escaped to `\aNNN`, and the result is packaged as a `.pmlz` (extension `pmlz`). HTML/SVG rendering (§5.5–5.6) is out of scope. Kobo (`flamberge-schemes::kobo`, module dir `db`/`content`/`mod`) reads the per-file wrapped page keys from the external Kobo library SQLite DB — threaded in as bytes via `KeyStore::kobo_db` (+ optional `kobo_volumeid`), since they live outside the book — patching the WAL header (bytes 18–19 → `01 01`) on a temp copy so `rusqlite` (bundled) opens it without a `-wal` sidecar; then per candidate `kobo_keys` user key it does two-layer AES-128-ECB (`user_key` → page key → member) + CMS/PKCS#7 strip, selecting the key by trial `check()` (xhtml printable-ASCII after BOM / jpeg `FF D8 FF`, sniffed by member extension) and repackaging via `ocf::repackage` → `.epub`. The **CLI** (`flamberge-cli`, split into `main`/`decrypt`/`keys`/`naming`/`autokeys`) is polished (TASK-18): `decrypt` takes one file, several files, or a directory (batch mode — per-file `OK`/`SKIP`/`FAIL` summary, exit 1 if any fail; unsupported files are `SKIP`, not failures; `--output` is single-input-only, `--output-dir` for batch), writes each output atomically (sibling `.part` temp + rename, so a failure never leaves a partial file), and `--auto-keys` best-effort-pulls local Adobe/Kobo/Kindle keys into the `KeyStore` before decrypting (each source's failure is warned to stderr, never fatal). All three `keys` subcommands run real extraction: `keys adobe` (macOS `activation.dat`), `keys kobo` (host discovery), `keys kindle` (decode `--k4i` / `--kinf`+`--user-name`/`--id-string`/`--platform` / `--android` artifacts; on-host `extract_local_keys` is still the only stub, surfaced with a hint when no artifact is given). Dispatch fall-through (`NotThisScheme` = keep looking, any other error = terminal and surfaced) lives in `schemes::decrypt` and is now unit-tested.
- **Stubbed** (return `Unimplemented`/`Unsupported`, doc-comment points at a spec §): on-host key-extraction only — `kindle::extract_local_keys` and the Adobe **Windows** live-DPAPI gathering (macOS `adobe::extract_keys` and Kobo `kobo::discover_userkeys` are real). (Mobipocket, Topaz, KFX, ADEPT EPUB+PDF, B&N EPUB+PDF, eReader, and Kobo KEPUB are all real; the Kindle `.k4i`/`.kinf`/Android **offline** paths, the Adobe macOS `activation.dat` path, and Kobo on-host key discovery are real — only Kindle local machine-value gathering / Windows DPAPI is stubbed.)
- **Next up:** on-host key-extraction (`kindle::extract_local_keys` §6 remainder, Adobe Windows live-DPAPI on a Windows host §7.2). CLI polish (TASK-18) is done; the cross-scheme integration suite (TASK-19) is done — all 9 scheme variants have an end-to-end round-trip + wrong-key negative in `flamberge-integration-tests`. All book-decryption schemes are now real; what remains is discovering/gathering the user keys on-host (DPAPI/plist/registry/ioreg paths, per the gotchas some are Windows-only and not reproducible offline). Note: KDF SQLite (`CONT`) → KFX-ZIP unpacking is out of scope (lives in the external KFX Input plugin); the KFX path here ingests `.kfx-zip` only; the ADEPT PDF `Adobe.APS`/Standard-V4 AES branch is likewise out of scope.

## Implementation gotchas (from the analysis)
- PC1 and Topaz require **wrapping u32 arithmetic** — the tested ports live in `flamberge-crypto`; reuse them, don't reinvent.
- ADEPT/B&N book keys are the **last 16 bytes** after PKCS#7 strip, not the first.
- ADEPT/B&N EPUB per-file decrypt **drops the first 16 bytes** (prepended IV block) before unpad + raw-inflate (windowBits −15).
- Topaz "encrypted" flag = the **sign of the record index** (negative), not a header field.
- All MOBI/PalmDB/ION/PDB integers are **big-endian**; treat every "string" as bytes.
- AES is **no-padding** everywhere; callers strip PKCS#7 themselves (`kdf::pkcs7_unpad`).
- Windows DPAPI paths (`.kinf2011` v5, Adobe `privateLicenseKey`) are **not reproducible offline** — they need the user's Windows profile.
- Scheme dispatch: by file extension, then Kindle-family magic bytes. A handler returns `SchemeError::NotThisScheme` to fall through to the next candidate.

<!-- CLAVIX:START -->
## Clavix Integration

This project uses Clavix for prompt improvement and PRD generation. The following slash commands are available:

> **Command Format:** Commands shown with colon (`:`) format. Some tools use hyphen (`-`): Claude Code uses `/clavix:improve`, Cursor uses `/clavix-improve`. Your tool autocompletes the correct format.

### Prompt Optimization

#### /clavix:improve [prompt]
Optimize prompts with smart depth auto-selection. Clavix analyzes your prompt quality and automatically selects the appropriate depth (standard or comprehensive). Use for all prompt optimization needs.

### PRD & Planning

#### /clavix:prd
Launch the PRD generation workflow. Clavix will guide you through strategic questions and generate both a comprehensive PRD and a quick-reference version optimized for AI consumption.

#### /clavix:plan
Generate an optimized implementation task breakdown from your PRD. Creates a phased task plan with dependencies and priorities.

#### /clavix:implement
Execute tasks or prompts with AI assistance. Auto-detects source: tasks.md (from PRD workflow) or prompts/ (from improve workflow). Supports automatic git commits and progress tracking.

Use `--latest` to implement most recent prompt, `--tasks` to force task mode.

### Session Management

#### /clavix:start
Enter conversational mode for iterative prompt development. Discuss your requirements naturally, and later use `/clavix:summarize` to extract an optimized prompt.

#### /clavix:summarize
Analyze the current conversation and extract key requirements into a structured prompt and mini-PRD.

### Refinement

#### /clavix:refine
Refine existing PRD or prompt through continued discussion. Detects available PRDs and saved prompts, then guides you through updating them with tracked changes.

### Agentic Utilities

These utilities provide structured workflows for common tasks. Invoke them using the slash commands below:

- **Verify** (`/clavix:verify`): Check implementation against PRD requirements. Runs automated validation and generates pass/fail reports.
- **Archive** (`/clavix:archive`): Archive completed work. Moves finished PRDs and outputs to archive for future reference.

**When to use which mode:**
- **Improve mode** (`/clavix:improve`): Smart prompt optimization with auto-depth selection
- **PRD mode** (`/clavix:prd`): Strategic planning with architecture and business impact

**Recommended Workflow:**
1. Start with `/clavix:prd` or `/clavix:start` for complex features
2. Refine requirements with `/clavix:refine` as needed
3. Generate tasks with `/clavix:plan`
4. Implement with `/clavix:implement`
5. Verify with `/clavix:verify`
6. Archive when complete with `/clavix:archive`

**Pro tip**: Start complex features with `/clavix:prd` or `/clavix:start` to ensure clear requirements before implementation.
<!-- CLAVIX:END -->

<!-- BACKLOG.MD MCP GUIDELINES START -->

<CRITICAL_INSTRUCTION>

## BACKLOG WORKFLOW INSTRUCTIONS

This project uses Backlog.md MCP for all task and project management activities.

**CRITICAL GUIDANCE**

- If your client supports MCP resources, read `backlog://workflow/overview` to understand when and how to use Backlog for this project.
- If your client only supports tools or the above request fails, call `backlog.get_backlog_instructions()` to load the tool-oriented overview. Use the `instruction` selector when you need `task-creation`, `task-execution`, or `task-finalization`.

- **First time working here?** Read the overview resource IMMEDIATELY to learn the workflow
- **Already familiar?** You should have the overview cached ("## Backlog.md Overview (MCP)")
- **When to read it**: BEFORE creating tasks, or when you're unsure whether to track work

These guides cover:
- Decision framework for when to create tasks
- Search-first workflow to avoid duplicates
- Links to detailed guides for task creation, execution, and finalization
- MCP tools reference

You MUST read the overview resource to understand the complete workflow. The information is NOT summarized here.

</CRITICAL_INSTRUCTION>

<!-- BACKLOG.MD MCP GUIDELINES END -->
