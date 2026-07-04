---
id: TASK-21
title: 'Avoid full Object clones in PdfDocument::get_object'
status: To Do
assignee: []
created_date: '2026-07-04 09:59'
labels:
  - formats
  - pdf
  - cleanup
dependencies: []
ordinal: 21000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Follow-up from the TASK-11 code review (PR #12). `flamberge-formats::pdf::PdfDocument::get_object` returns a full `Object` clone on every call, including a stream's entire `rawdata` buffer. `resolve()` calls it once per reference hop and `PdfSerializer::serialize` calls it once per object id, so resolving/serializing a document with large streams multiplies memory traffic by cloning multi-megabyte bodies repeatedly.

Change the object cache and `get_object` to hand back a shared handle (e.g. `Rc<Object>`) instead of a deep clone, so callers share one allocation. This ripples through `resolve`, `PdfSerializer`, `parse_from_objstm`, and the module's tests — all of which currently assume owned `Object` values — so it is deliberately kept out of the review-fix commit and tracked here.

Note: a cheaper related win (caching `/N` so `parse_from_objstm` no longer re-clones the ObjStm container) was already fixed in PR #12; this task is specifically the `get_object` return-type change. Scope is `crates/flamberge-formats/src/pdf/` only.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 get_object (and the object cache) return a shared handle instead of a deep Object clone, so repeated resolution/serialization of large streams does not re-clone stream bodies
- [ ] #2 resolve(), PdfSerializer, and parse_from_objstm are updated to the new return type without behavioural change
- [ ] #3 A test demonstrates that resolving the same large-stream object twice does not deep-copy its rawdata (e.g. via shared-handle identity or an allocation-sensitive assertion)
- [ ] #4 Existing pdf module tests and the real-PDF round trips still pass; cargo build/test/clippy/fmt are clean
- [ ] #5 Public items keep doc comments; no panic!/unwrap/expect on non-test paths
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
