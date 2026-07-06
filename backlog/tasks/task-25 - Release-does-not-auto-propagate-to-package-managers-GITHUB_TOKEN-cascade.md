---
id: TASK-25
title: Release does not auto-propagate to package managers (GITHUB_TOKEN cascade)
status: Done
assignee: []
created_date: '2026-07-06 07:23'
updated_date: '2026-07-06 07:26'
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
- [x] #1 package-managers.yml triggers on workflow_run of the Release workflow (types: completed) and still supports manual workflow_dispatch with a tag input
- [x] #2 TAG is derived from github.event.workflow_run.head_branch on auto-runs and from the dispatch input on manual runs
- [x] #3 Jobs run only when the Release run concluded 'success' on a v* tag (or on manual dispatch), so non-tag Release runs do not propagate
- [x] #4 YAML validates; the secret-presence step gates are preserved so jobs still no-op without their secrets
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Fixed in PR #28. `package-managers.yml` now triggers on `workflow_run` of the Release workflow (types: completed) plus the existing `workflow_dispatch`; `TAG` comes from `github.event.workflow_run.head_branch` on auto-runs and the dispatch input on manual runs; each job is gated on a successful `v*`-tagged Release run (or manual dispatch), and the per-secret step gates are unchanged so jobs still no-op without their secrets. Runbook + CLAUDE.md updated to describe the `workflow_run` trigger and the GITHUB_TOKEN-no-cascade reason.

No Rust changed (CI-config only), so build/test/clippy are unaffected (workspace was green at 256 tests on the preceding commit); DoD#5 (DEDRM_SCHEMES.md) is N/A for a CI change. The fix takes effect once merged (workflow_run runs from the default branch); it does not retroactively propagate v0.1.1, which is handled via `gh workflow run "Package managers" -f tag=v0.1.1`.
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
