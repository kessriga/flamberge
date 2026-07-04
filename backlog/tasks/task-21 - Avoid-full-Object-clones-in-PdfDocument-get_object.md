---
id: TASK-21
title: 'Avoid full Object clones in PdfDocument::get_object'
status: Done
assignee:
  - Kessriga Jeükal
created_date: '2026-07-04 09:59'
updated_date: '2026-07-04 22:21'
labels:
  - formats
  - pdf
  - cleanup
dependencies: []
modified_files:
  - crates/flamberge-formats/src/pdf/document.rs
  - crates/flamberge-formats/src/pdf/parser.rs
  - crates/flamberge-schemes/src/pdf_common.rs
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
- [x] #1 get_object (and the object cache) return a shared handle instead of a deep Object clone, so repeated resolution/serialization of large streams does not re-clone stream bodies
- [x] #2 resolve(), PdfSerializer, and parse_from_objstm are updated to the new return type without behavioural change
- [x] #3 A test demonstrates that resolving the same large-stream object twice does not deep-copy its rawdata (e.g. via shared-handle identity or an allocation-sensitive assertion)
- [x] #4 Existing pdf module tests and the real-PDF round trips still pass; cargo build/test/clippy/fmt are clean
- [x] #5 Public items keep doc comments; no panic!/unwrap/expect on non-test paths
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Change the object cache + `get_object` to hand back `Rc<Object>` instead of a deep `Object` clone; ripple through `resolve`, `PdfSerializer`, `parse_from_objstm`, and the two `parser.rs` shallow-resolve callers.

**document.rs**
- `use std::rc::Rc;`
- `cache: RefCell<HashMap<u32, Rc<Object>>>`.
- `get_object(&self, objid) -> Result<Rc<Object>>`: cache hit → `Rc::clone`; on miss build a fresh `Object`, wrap once in `Rc`, insert `Rc::clone` into cache, return. `build_object`/`parse_indirect_at`/`parse_from_objstm` keep returning owned `Object` (the Rc wrap happens once in `get_object`).
- `parse_from_objstm`: `self.get_object(stmid)?` now yields `Rc<Object>`; match on `container.as_ref()`. Member lookup still `.cloned()` (small member, not the container body — the container's `rawdata` is no longer re-cloned per member because it is only fetched once, shared).
- `resolve(&self, obj: &Object) -> Result<Rc<Object>>`: if input is a direct object, `Rc::new(obj.clone())` (one small clone of the borrowed input, documented); if a `Ref`, loop through `get_object` returning the shared cached `Rc`, bounded reference-cycle guard preserved.

**parser.rs**
- L136 `/Length` resolve: `.and_then(|o| match o.as_ref() { Object::Int(n) if *n >= 0 => Some(*n as usize), _ => None })`.
- `resolve_shallow` (L223/227): `doc.get_object(objid).map(|o| (*o).clone()).unwrap_or(Object::Null)` — still returns owned `Object`; the resolved values here are tiny scalars/arrays (/Length, /Filter, /DecodeParms), so the clone is negligible.

**serializer.rs**: `obj` becomes `Rc<Object>`; `obj.type_name()` and `write_object(&mut out, &obj)` both work via `Deref`/deref-coercion, no signature change.

**pdf_common.rs**: `doc.resolve(...)` now `Rc<Object>`; L62-66 change `.and_then(Object::as_int)` → `.and_then(|o| o.as_int())` (fn-ptr can't take `&Rc<Object>`). Other uses work via `Deref`.

**Test (AC#3)**: add a document.rs test that builds a PDF with a large stream object, calls `get_object(id)` twice, and asserts `Rc::ptr_eq(&h1, &h2)` — proving the second fetch shares the allocation instead of deep-copying `rawdata`.

Verify: cargo build/test/clippy/fmt clean across the workspace; existing pdf + real-PDF round-trip tests still pass.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented: `get_object` and the `cache` now hand back `Rc<Object>` (refcount bump on cache hit, single `Rc::new` on miss). `resolve` returns `Rc<Object>` (cached handle for a Ref input; one small clone of the borrowed arg for a direct input). `parse_from_objstm` matches the container via `container.as_ref()`. Ripple was minimal thanks to deref coercion — only two `parser.rs` sites (the `/Length` match → `o.as_ref()`; `resolve_shallow` → `.map(|o| (*o).clone())`) and one `pdf_common.rs` site (`.and_then(Object::as_int)` → closure, since a bare fn-ptr can't take `&Rc<Object>`) needed edits. Serializer needed no signature change. Added `repeated_get_object_shares_one_allocation` (AC#3): two fetches of a 200 KB stream object return `Rc::ptr_eq` handles, and `resolve(&Ref(4,0))` yields that same shared handle. cargo build/test (all 6 binaries + integration suite)/clippy -D warnings/fmt all clean.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
`PdfDocument`'s object cache and `get_object` now return `Rc<Object>` instead of a deep `Object` clone. A cache hit is an `Rc` refcount bump; on a miss the freshly-built object is wrapped once in an `Rc` and shared. This removes the repeated deep-copy of large stream `rawdata` buffers that `resolve()` (once per reference hop) and `PdfSerializer::serialize` (once per object id) previously incurred.

Ripple:
- `resolve()` returns `Rc<Object>` — the cached shared handle for an indirect reference, or a single clone of the (small, borrowed) argument for a direct-object input. The bounded reference-cycle guard is preserved.
- `parse_from_objstm` matches the container through `container.as_ref()`.
- `parser.rs`: the `/Length` indirect-resolve matches via `o.as_ref()`; `resolve_shallow` clones out of the handle (`(*o).clone()`) since it still yields owned `Object` for tiny scalar/array values.
- `pdf_common.rs`: `.and_then(Object::as_int)` became a closure (a bare `fn(&Object)` pointer can't accept `&Rc<Object>`).
- `PdfSerializer` needed no signature change — deref coercion covers `obj.type_name()` and `write_object(&mut out, &obj)`.

Test: `repeated_get_object_shares_one_allocation` builds a PDF with a 200 KB stream object, fetches it twice, and asserts `Rc::ptr_eq` on the two handles (and that `resolve(&Ref(4,0))` yields the same handle) — proving the body is not re-cloned.

Verification: `cargo build`, `cargo test` (all unit binaries + the 55-test integration suite = the real-PDF round trips), `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo fmt --all -- --check` all clean. Scope stayed within `crates/flamberge-formats/src/pdf/` plus the one unavoidable `pdf_common.rs` caller fix.
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
