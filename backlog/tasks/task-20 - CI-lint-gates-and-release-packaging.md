---
id: TASK-20
title: 'CI, lint gates, and release packaging'
status: Done
assignee: []
created_date: '2026-07-03 20:01'
updated_date: '2026-07-05 08:21'
labels:
  - ci
  - release
  - docs
milestone: m-5
dependencies: []
references:
  - README.md
modified_files:
  - .github/workflows/release.yml
  - README.md
  - LICENSE
priority: low
ordinal: 20000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Set up continuous integration and release. Add a CI workflow that runs `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, and `cargo fmt --check` on Linux/macOS/Windows. Add release packaging: build optimized binaries per platform and attach them to tagged releases (and/or publish libs to crates.io if desired). Update README with install instructions and a usage matrix of supported schemes/platforms, and add a short LICENSE/legal-use note. This task can be started early; the lint gates should pass against the current tree.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 CI runs build + test + clippy(-D warnings) + fmt --check on Linux/macOS/Windows and is green on the current tree
- [x] #2 Tagged releases produce optimized per-platform `flamberge` binaries as downloadable artifacts
- [x] #3 README documents install, usage, and a supported-scheme/platform matrix; a legal-use note is present
- [x] #4 License is set consistently across crates (workspace `license`) and a LICENSE file exists
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
CI gates landed on `feat/rust-port` (.github/workflows/ci.yml): a `lint` job (`cargo fmt --all -- --check` + `cargo clippy --workspace --all-targets -- -D warnings`) on Linux, and a `test` matrix (`cargo build --workspace --all-targets` + `cargo test --workspace`) across ubuntu/macos/windows-latest; triggers on pushes to main and all PRs. Applied `cargo fmt --all` to make the tree format-clean so the gate passes. AC#1 satisfied pending a green run on GitHub. Still open: AC#2 release packaging (tagged per-platform `flamberge` binaries), AC#3 README install/usage/scheme-platform matrix + legal note, AC#4 LICENSE file (workspace `license` is already GPL-3.0-or-later).

Completed AC#2-4. AC#2: added `.github/workflows/release.yml` — on `v*` tag push (or manual `workflow_dispatch` smoke-test) it builds `cargo build --release --locked -p flamberge-cli` across a 4-target matrix (x86_64 Linux, aarch64 + x86_64 macOS, x86_64 Windows), packages `flamberge`(.exe)+README+LICENSE into a per-target `.tar.gz`/`.zip`, and attaches assets to the tag's GitHub release via softprops/action-gh-release@v2 (upload guarded by `startsWith(github.ref,'refs/tags/')`, `fail_on_unmatched_files: true`). AC#4: added top-level `LICENSE` (verbatim canonical GPLv3 text); workspace `license = GPL-3.0-or-later` was already set and every crate inherits via `license.workspace = true`. AC#3: reworked README — new `## Install` section (release-binary download + `cargo install --path` + build-from-source), a `## Supported schemes` table (scheme × input/output/key-source, all 9 variants) and a `## Key extraction by platform` matrix (Linux/macOS/Windows, marking the Windows-DPAPI / on-host-machine-value paths that aren't reproducible offline); the personal-use legal note already present at the top of the README was retained. Verified: fmt --check clean, clippy -D warnings clean, full `cargo test --workspace` green; no Rust code changed.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
CI/lint gates (AC#1) had already landed. This closes out the release + docs work:

- **Release packaging (AC#2):** `.github/workflows/release.yml` builds optimized per-platform `flamberge` binaries (Linux x86_64, macOS arm64+x86_64, Windows x86_64) on `v*` tags and attaches `.tar.gz`/`.zip` archives (binary + README + LICENSE) to the GitHub release. `workflow_dispatch` runs the matrix without uploading, for smoke-testing.
- **README (AC#3):** added Install (pre-built binaries + from-source), a supported-schemes table, and a per-platform key-extraction matrix; kept the personal-use legal note.
- **License (AC#4):** added a verbatim GPLv3 `LICENSE` file; the workspace `license = GPL-3.0-or-later` (inherited by every crate) was already consistent.

No Rust changed; fmt/clippy/`cargo test --workspace` all green. This was the last open task.
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
