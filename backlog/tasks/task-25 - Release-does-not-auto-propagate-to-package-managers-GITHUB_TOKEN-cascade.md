---
id: TASK-25
title: Release does not auto-propagate to package managers (GITHUB_TOKEN cascade)
status: In Progress
assignee: []
created_date: '2026-07-06 07:23'
labels:
  - release
  - packaging
  - ci
  - bug
dependencies: []
references:
  - .github/workflows/package-managers.yml
  - .github/workflows/release.yml
priority: high
ordinal: 25000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up to TASK-24. On the v0.1.1 release the `Package managers` workflow never ran, so the Homebrew tap / Chocolatey / winget propagation did not fire (the tap repo stayed empty). crates.io publish + binary/.deb/.rpm/SHA256SUMS attach all worked (they live in release.yml, triggered directly by the tag push).

Root cause: `package-managers.yml` triggers on `release: published`, but the release is created by `softprops/action-gh-release` using the built-in `GITHUB_TOKEN`, and GitHub does not cascade `GITHUB_TOKEN`-created events into new workflow runs. So the `release: published` event never fired.

Fix: retrigger `package-managers.yml` off the Release workflow's completion via `workflow_run` (which does fire regardless of the triggering token), keeping the manual `workflow_dispatch` path. Derive the tag from `github.event.workflow_run.head_branch` (the tag name for a tag-triggered run) or the dispatch input, and gate the jobs on a successful, `v*`-tagged Release run.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 package-managers.yml triggers on workflow_run of the Release workflow (types: completed) and still supports manual workflow_dispatch with a tag input
- [ ] #2 TAG is derived from github.event.workflow_run.head_branch on auto-runs and from the dispatch input on manual runs
- [ ] #3 Jobs run only when the Release run concluded 'success' on a v* tag (or on manual dispatch), so non-tag Release runs do not propagate
- [ ] #4 YAML validates; the secret-presence step gates are preserved so jobs still no-op without their secrets
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
