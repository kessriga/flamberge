---
id: TASK-19
title: Cross-scheme integration test suite + fixtures
status: To Do
assignee: []
created_date: '2026-07-03 20:01'
labels:
  - testing
milestone: m-5
dependencies: []
references:
  - docs/DEDRM_SCHEMES.md
modified_files:
  - tests/
priority: low
ordinal: 19000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Build a workspace-level integration test suite (top-level `tests/`) that exercises each implemented scheme end-to-end through `flamberge_schemes::decrypt` (and/or the CLI binary), plus a shared fixtures module for synthesizing small encrypted books per scheme (constructed by the project's own crypto, with provenance documented). Each scheme adds its case as it lands; this task establishes the harness and the fixture helpers, and backfills cases for already-implemented schemes. Include negative tests (wrong key → clean failure) and a golden-output check where practical.

Note: real DRMed books cannot be committed; fixtures are synthesized. Depends conceptually on scheme tasks but the harness can be built first and grown.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A `tests/` harness with a fixtures module can synthesize a small encrypted book for each scheme using the project's crypto
- [ ] #2 Every implemented scheme has an end-to-end decrypt test asserting recovered content
- [ ] #3 Negative tests confirm wrong keys fail cleanly with no output file
- [ ] #4 Fixture provenance/synthesis is documented; no non-redistributable content is committed
- [ ] #5 `cargo test` runs the suite in CI
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
