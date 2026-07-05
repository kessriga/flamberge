---
id: TASK-24
title: >-
  Package-manager distribution (Homebrew, winget, Chocolatey, mise, Linux
  packages)
status: Done
assignee: []
created_date: '2026-07-05 08:51'
updated_date: '2026-07-05 13:11'
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
- [x] #1 release.yml also emits SHA256 checksums and .deb + .rpm artifacts with stable, convention-following asset names, attached to each tagged release
- [ ] #2 `cargo install flamberge-cli` works (crates.io publish) and `cargo install --path crates/flamberge-cli` is documented
- [ ] #3 A Homebrew formula (tap or homebrew-core) installs a working `flamberge` on macOS and Linux
- [x] #4 `flamberge` is installable via mise over the GitHub release (ubi/aqua backend), documented in the README
- [ ] #5 A winget manifest is accepted and `winget install` yields a working `flamberge` on Windows
- [ ] #6 A Chocolatey package is published and `choco install flamberge` works on Windows
- [ ] #7 At least one Linux distro path beyond the raw archive works (e.g. AUR PKGBUILD and/or the attached .deb/.rpm), documented
- [x] #8 README install section lists every supported manager with the exact install command; a note documents how a release propagates version/hash bumps to each
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Scope (user-approved): full in-repo staging + handoff runbook. Registry submissions that need accounts/tokens (crates.io publish, Homebrew tap, winget-pkgs PR, Chocolatey push, AUR) are staged + automated but executed by the maintainer; documented in packaging/README.md.

1. Cargo metadata for crates.io publish: add description/repository/readme/keywords/categories/homepage to the 4 libs + CLI; give workspace-internal deps `version = "0.1.0"` alongside `path`; add `[package.metadata.deb]` + `[package.metadata.generate-rpm]` to flamberge-cli. (AC#2 prep)
2. release.yml: Linux job also builds .deb (cargo-deb) + .rpm (cargo-generate-rpm); every asset gets a .sha256 sidecar; a final `checksums` job aggregates SHA256SUMS; add a tag-gated `publish-crates` job (skips without CARGO_REGISTRY_TOKEN) and release-triggered winget-releaser / homebrew bump / choco push, each skipping when its secret/tap is absent. (AC#1)
3. packaging/ staged definitions against the real v0.1.0 assets (real URLs+sha256): homebrew/flamberge.rb (macOS-arm64 + Linux-x86_64), winget/ (3 manifests, Kessriga.Flamberge), chocolatey/ (nuspec + install/uninstall ps1), aur/PKGBUILD + .SRCINFO. Archives nest under flamberge-v0.1.0-<target>/, formulas must cd into it.
4. Docs: README install section (one exact command per manager) + packaging/README.md runbook incl. version/hash propagation-on-release note. (AC#8)

Real v0.1.0 SHA256: macos-arm64 tar.gz 084e6aa2...b954ab; linux-x86_64 tar.gz b01bbff8...df89a8; windows-x86_64 zip 2521ccca...9329b5.

Verify here: cargo build/test/clippy/fmt green; TOML/YAML parse; cargo-deb/generate-rpm dry-run if installable. "install works" ACs (#3/#5/#6/#7, crates.io half of #2) are staged-and-blocked-on-maintainer-submission, tracked in the runbook.
<!-- SECTION:PLAN:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Delivered the full in-repo staging + maintainer runbook for package-manager distribution (scope chosen by the user: registry submissions that need accounts/tokens are staged + automated but executed by the maintainer).

**Done & verified in-repo (checked ACs):**
- **AC#1** — `release.yml` now builds a Linux `.deb` (cargo-deb) + `.rpm` (cargo-generate-rpm), aggregates all assets into `SHA256SUMS`, and (new `publish-crates` job) publishes the workspace to crates.io in dependency order. Verified locally: both packages build and install the binary at `/usr/bin/flamberge`.
- **AC#4** — mise: usable now via `mise use -g ubi:kessriga/flamberge` over the existing release; documented in README.
- **AC#8** — README carries an install table with the exact command per manager; `packaging/README.md` documents the release→manager propagation.

**Staged, blocked on maintainer account/registry actions (unchecked ACs #2/#3/#5/#6/#7):** package definitions written against the real v0.1.0 assets (real URLs + SHA256) — `packaging/homebrew/flamberge.rb` (+ reproducible `update-homebrew-formula.sh`, byte-for-byte verified), `packaging/winget/` (3-manifest nested-portable zip), `packaging/chocolatey/` (nuspec + install/uninstall + VERIFICATION), `packaging/aur/` (PKGBUILD + .SRCINFO). `package-managers.yml` auto-propagates each published release to winget/Homebrew/Chocolatey, each job a no-op until its secret exists. The literal "install works" criteria require the maintainer to: publish to crates.io (`CARGO_REGISTRY_TOKEN`), create the `kessriga/homebrew-flamberge` tap (`HOMEBREW_TAP_TOKEN`), submit to winget-pkgs (`WINGET_TOKEN`), push to chocolatey.org (`CHOCO_API_KEY`), and push the AUR repo — all itemized in `packaging/README.md`.

**Metadata enablement:** every crate got description/repository/homepage/keywords/categories; internal path-deps carry `version = "0.1.0"` so the workspace is publishable; flamberge-cli gained `[package.metadata.deb]`/`[package.metadata.generate-rpm]` (package name `flamberge`) + a crates.io README.

Gates green: `cargo fmt --check`, `cargo clippy --workspace --all-targets -D warnings`, `cargo test --workspace` (256 tests), `cargo publish --dry-run` (leaf crate), YAML lint. DoD#5 (DEDRM_SCHEMES.md) is N/A — this task is packaging/CI config with no scheme behavior; DoD#6 satisfied (no new public API; new files carry header docs).
<!-- SECTION:FINAL_SUMMARY:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 cargo build succeeds with no warnings
- [x] #2 cargo test passes (unit and integration)
- [x] #3 cargo clippy passes with no warnings
- [x] #4 no panic!/unwrap/expect on non-test code paths
- [ ] #5 behavior matches docs/DEDRM_SCHEMES.md and code cites the relevant section
- [ ] #6 public items have doc comments
<!-- DOD:END -->
