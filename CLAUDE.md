# flamberge — Project Guide

Standalone Rust CLI that reimplements the **DeDRM_tools** Calibre plugins (ebook DRM removal).

## Sources of truth
- `docs/DEDRM_SCHEMES.md` — **the spec.** Byte-level reference for every scheme (offsets, constants, key derivation). **Read the relevant section before implementing any scheme.** Sections: §1 crypto, §2 Mobipocket, §3 KFX/ION, §4 B&N, §5 Topaz, §6 Kindle keys, §7 Adobe ADEPT, §8 eReader, §9 Kobo, §10 Rust guidance.
- `docs/ai/STATUS.md` — the detailed **implementation status** (what's real vs stub vs next-up). Consult it to see what's already built before starting work.
- `../../external/DeDRM_tools/DeDRM_plugin/` — the original Python source the spec was derived from; consult it when the spec is ambiguous.

## Working conventions
- Tasks live in **Backlog.md** (`backlog/tasks/`). Per task: mark In Progress, record a plan in the task, implement with tests, verify build/test/clippy/fmt, mark Done with a final summary.
- **You may create Backlog tasks on your own initiative** — e.g. to capture a review follow-up, split out discovered scope, or track a cleanup — without asking first. Prefer this over silently expanding a task's scope. (This overrides the generic Backlog-MCP guidance about not creating tasks unprompted.)
- **You may add dependencies to the project when a task genuinely needs one** (a workspace crate under `[workspace.dependencies]`, then referenced with `.workspace = true` in the crate's `Cargo.toml`). Favour well-maintained, widely-used crates; keep the dependency surface small and note why in the task/commit. No need to ask first.
- **When finishing a task, update this CLAUDE.md and [`docs/ai/STATUS.md`](docs/ai/STATUS.md) too** if the completed work changed anything documented in them (e.g. the status breakdown, conventions, or gotchas). Skip only when there is genuinely nothing to update.
- **Commits: atomic and reasonably short** — one logical change per commit, your judgment on boundaries. Keep unrelated cleanups (e.g. lint fixes) in their own commits.
- **Separate concerns into separate modules whenever possible** — favour a module-per-concern layout (e.g. lexer / parser / object model / serializer each in their own file under a `foo/` module dir) over one large file. Scope internal items `pub(super)` and re-export only the genuine public API from `mod.rs`; keep each module's tests beside it.
- **One branch per task**, cut from `main` (e.g. `feat/task-4-topaz`); never commit to `main` directly. `main` is protected — integrate via PR only, with CI green and commits signed. Commit signing (SSH) is configured globally, so commits sign automatically.
  - **Before starting a task:** switch to `main`, pull, then create and switch to the task branch.
  - **After the task is done, before opening the PR:** pull `main` and rebase the task branch onto it.

## Layout & commands
- Cargo workspace under `crates/`; dependency direction: `flamberge-crypto` ← `flamberge-formats`, `flamberge-keys` ← `flamberge-schemes` ← `flamberge` (the CLI crate, published + binary name both `flamberge`, living in dir `crates/flamberge-cli`).
- `cargo build` / `cargo test` from repo root. Unit tests are colocated in each module; every cipher has a round-trip test. The workspace-level, cross-scheme end-to-end suite lives in the `flamberge-integration-tests` crate (`publish = false`): `src/fixtures/` synthesizes a DRM-encrypted book per scheme from the project's own crypto (fixtures are a `pub` lib, not `tests/common/`, to dodge the integration-test dead-code-warning footgun and because an external test crate can't see a scheme's `#[cfg(test)]` builders), and `tests/schemes.rs` decrypts each through `flamberge_schemes::decrypt` + asserts a wrong key fails cleanly.
- CI (`.github/workflows/ci.yml`) gates every PR: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and build+test on Linux/macOS/Windows. Run `cargo fmt` before committing — warnings and unformatted code fail the merge. Releases: pushing a `v*` tag runs `.github/workflows/release.yml`, which builds an optimized `flamberge` per platform (x86_64 Linux, arm64 macOS, x86_64 Windows), attaches `.tar.gz`/`.zip` archives plus a Linux `.deb`/`.rpm` and an aggregate `SHA256SUMS`, and publishes the workspace to crates.io (skipped until `CARGO_REGISTRY_TOKEN` is set). `.github/workflows/package-managers.yml` (triggered by the Release workflow completing via `workflow_run`, **not** `release: published` — GITHUB_TOKEN-created releases don't cascade events; also runnable via `workflow_dispatch -f tag=vX.Y.Z`) then propagates the release to winget/Homebrew/Chocolatey — each job a no-op until its secret exists. Package definitions (Homebrew formula, winget/Chocolatey manifests, AUR PKGBUILD, deb/rpm metadata) and the maintainer runbook live under `packaging/`; the CLI crate carries `[package.metadata.deb]`/`[package.metadata.generate-rpm]` and internal workspace deps carry `version` alongside `path` so the crates are publishable. TASK-24 completed the in-repo staging; the registry submissions themselves are maintainer/account-gated (see `packaging/README.md`). Top-level `LICENSE` is the MIT license; the workspace `license = MIT` (inherited by every crate via `license.workspace = true`).
- Errors: `thiserror` in libs, `anyhow` in the CLI. Never `panic!`/`unwrap` on a real code path.

## Status (what's real vs stub)
The detailed real / stub / next-up breakdown lives in [`docs/ai/STATUS.md`](docs/ai/STATUS.md). Read it before starting work to see what's already implemented, and keep it current when a task changes what's real (per the working conventions above). In short: every book-decryption scheme (Mobipocket, Topaz, KFX, Adobe ADEPT EPUB+PDF, B&N EPUB+PDF, eReader, Kobo KEPUB) is real and tested; the only stubs are on-host key gathering — `kindle::extract_local_keys` and Adobe **Windows** live-DPAPI.

## Implementation gotchas (from the analysis)
- PC1 and Topaz require **wrapping u32 arithmetic** — the tested ports live in `flamberge-crypto`; reuse them, don't reinvent.
- ADEPT/B&N book keys are the **last 16 bytes** after PKCS#7 strip, not the first.
- ADEPT/B&N EPUB per-file decrypt **drops the first 16 bytes** (prepended IV block) before unpad + raw-inflate (windowBits −15).
- Topaz "encrypted" flag = the **sign of the record index** (negative), not a header field.
- All MOBI/PalmDB/ION/PDB integers are **big-endian**; treat every "string" as bytes.
- AES is **no-padding** everywhere; callers strip PKCS#7 themselves (`kdf::pkcs7_unpad`).
- Windows DPAPI paths (`.kinf2011` v5, Adobe `privateLicenseKey`) are **not reproducible offline** — they need the user's Windows profile.
- Scheme dispatch: by file extension, then Kindle-family magic bytes. A handler returns `SchemeError::NotThisScheme` to fall through to the next candidate.

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
