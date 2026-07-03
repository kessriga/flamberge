---
id: TASK-18
title: 'CLI polish: batch mode, auto key-discovery, wired key subcommands'
status: To Do
assignee: []
created_date: '2026-07-03 20:00'
labels:
  - cli
milestone: m-5
dependencies:
  - TASK-15
  - TASK-16
  - TASK-17
references:
  - docs/DEDRM_SCHEMES.md
modified_files:
  - crates/dedrm-cli/src/main.rs
  - crates/dedrm-schemes/src/lib.rs
priority: low
ordinal: 18000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Round out the `dedrm` binary. Wire the `keys adobe`/`keys kindle`/`keys kobo` subcommands to the now-implemented extraction (tasks 15-17) instead of returning bail!. Add optional auto key-discovery to `decrypt` (a flag that pulls local Kindle/Adobe/Kobo keys into the KeyStore before trying). Add batch mode: accept a directory or multiple inputs and decrypt each, reporting a per-file summary. Improve dispatch so a non-matching scheme returns NotThisScheme (not a hard error) and the surfaced error is the most relevant one. Ensure no partial output files are left on failure.

Depends on the key-extraction tasks for the subcommand wiring. Spec: docs/DEDRM_SCHEMES.md §0 (dispatch).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `keys adobe|kindle|kobo` run the real extraction and print/store discovered keys
- [ ] #2 `decrypt --auto-keys` (or equivalent) pulls local keys into the KeyStore before attempting decryption
- [ ] #3 Batch mode decrypts a directory / multiple files and prints a per-file success/failure summary with a correct exit code
- [ ] #4 Non-matching schemes fall through via NotThisScheme; failures never leave a partial output file
- [ ] #5 Tests cover batch dispatch and the fall-through/most-relevant-error behavior
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
