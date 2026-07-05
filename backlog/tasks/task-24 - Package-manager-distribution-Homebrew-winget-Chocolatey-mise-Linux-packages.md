---
id: TASK-24
title: >-
  Package-manager distribution (Homebrew, winget, Chocolatey, mise, Linux
  packages)
status: To Do
assignee: []
created_date: '2026-07-05 08:51'
labels:
  - release
  - packaging
  - docs
milestone: m-5
dependencies:
  - TASK-20
references:
  - README.md
  - .github/workflows/release.yml
priority: low
ordinal: 24000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Make `flamberge` installable through the major package managers, beyond the raw release archives that TASK-20 produces.

`cargo install` already works (binary crate `flamberge-cli`) and is documented; publishing to crates.io would make `cargo install flamberge-cli` work without `--path`. Everything else below depends on a **published GitHub release** (tagged binaries + SHA256 checksums from `release.yml`) and, for most managers, an **external repo/registry plus an account** — so these cannot be fully wired or verified inside the TASK-20 release PR and are tracked here.

Managers in scope:
- **cargo** — publish libs+CLI to crates.io so `cargo install flamberge-cli` works; document. (Also keep `cargo install --path` for from-source.)
- **Homebrew** (macOS + Linux) — a formula that installs the release binary. Either a personal tap repo (`kessriga/homebrew-flamberge`) or, if notability criteria are met, submit to `homebrew-core`. Formula references the release tarball URL + sha256; consider automating bumps with a bottle/`brew bump-formula-pr` or a `dispatch` from `release.yml`.
- **mise** — installable via mise's `ubi`/`aqua` backend over GitHub releases (needs consistently-named assets + checksums), or a `cargo:` backend entry. Document `mise use ubi:kessriga/flamberge` (or the registry short name once added).
- **winget** — a manifest submitted to `microsoft/winget-pkgs` referencing a published installer/zip + SHA256. Consider `vedantmgoyal9/winget-releaser` to automate the PR from `release.yml`.
- **Chocolatey** — a `.nuspec`/`chocolateyInstall.ps1` package pushed to chocolatey.org (needs an account + API key stored as a repo secret).
- **Linux distro packages** — attach `.deb` (via `cargo-deb`) and `.rpm` (via `cargo-generate-rpm`) to releases; an AUR `PKGBUILD` in a separate AUR repo; optionally a Nix flake / nixpkgs entry.

Release-workflow prep that *can* be done in-repo (and unblocks the external submissions): extend `release.yml` to also emit `SHA256SUMS`, `.deb`, and `.rpm` artifacts with stable, convention-following asset names that `ubi`/Homebrew/winget can consume.

Note ongoing maintenance cost: every tagged release must propagate a version+hash bump to each manager (ideally automated from `release.yml`).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 release.yml also emits SHA256 checksums and .deb + .rpm artifacts with stable, convention-following asset names, attached to each tagged release
- [ ] #2 `cargo install flamberge-cli` works (crates.io publish) and `cargo install --path crates/flamberge-cli` is documented
- [ ] #3 A Homebrew formula (tap or homebrew-core) installs a working `flamberge` on macOS and Linux
- [ ] #4 `flamberge` is installable via mise over the GitHub release (ubi/aqua backend), documented in the README
- [ ] #5 A winget manifest is accepted and `winget install` yields a working `flamberge` on Windows
- [ ] #6 A Chocolatey package is published and `choco install flamberge` works on Windows
- [ ] #7 At least one Linux distro path beyond the raw archive works (e.g. AUR PKGBUILD and/or the attached .deb/.rpm), documented
- [ ] #8 README install section lists every supported manager with the exact install command; a note documents how a release propagates version/hash bumps to each
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
