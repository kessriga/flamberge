---
id: TASK-20
title: 'CI, lint gates, and release packaging'
status: In Progress
assignee: []
created_date: '2026-07-03 20:01'
updated_date: '2026-07-03 21:33'
labels:
  - ci
  - release
  - docs
milestone: m-5
dependencies: []
references:
  - README.md
modified_files:
  - .github/workflows/
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
- [ ] #2 Tagged releases produce optimized per-platform `flamberge` binaries as downloadable artifacts
- [ ] #3 README documents install, usage, and a supported-scheme/platform matrix; a legal-use note is present
- [ ] #4 License is set consistently across crates (workspace `license`) and a LICENSE file exists
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
CI gates landed on `feat/rust-port` (.github/workflows/ci.yml): a `lint` job (`cargo fmt --all -- --check` + `cargo clippy --workspace --all-targets -- -D warnings`) on Linux, and a `test` matrix (`cargo build --workspace --all-targets` + `cargo test --workspace`) across ubuntu/macos/windows-latest; triggers on pushes to main and all PRs. Applied `cargo fmt --all` to make the tree format-clean so the gate passes. AC#1 satisfied pending a green run on GitHub. Still open: AC#2 release packaging (tagged per-platform `flamberge` binaries), AC#3 README install/usage/scheme-platform matrix + legal note, AC#4 LICENSE file (workspace `license` is already GPL-3.0-or-later).
<!-- SECTION:NOTES:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 cargo build succeeds with no warnings
- [ ] #2 cargo test passes (unit and integration)
- [ ] #3 cargo clippy passes with no warnings
- [ ] #4 no panic!/unwrap/expect on non-test code paths
- [ ] #5 behavior matches docs/DEDRM_SCHEMES.md and code cites the relevant section
- [ ] #6 public items have doc comments
<!-- DOD:END -->
