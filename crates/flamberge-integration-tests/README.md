# flamberge-integration-tests

Workspace-level, cross-scheme end-to-end test suite for Flamberge. Not published
(`publish = false`); compiled only by `cargo test` / `cargo clippy`.

`tests/schemes.rs` decrypts a synthesized DRM-encrypted book for **every**
implemented scheme through the top-level `flamberge_schemes::decrypt` dispatch
(so it also exercises extension routing and key handling), asserts the recovered
content, and confirms a wrong/empty key fails cleanly (`Err(NoKeyWorked)`, no
book produced). Schemes covered: Mobipocket, Topaz, KFX, Adobe ADEPT (EPUB + PDF),
Barnes & Noble (EPUB + PDF), eReader, Kobo.

## Fixture provenance

**No fixture contains any real, DRM-protected book** — shipping one would mean
redistributing copyrighted, DRMed content. Every fixture in `src/fixtures/` is
constructed at run time from this project's own crypto primitives
(`flamberge-crypto`) and public format helpers, wrapping a short synthetic
plaintext under a key the test itself controls. The byte layouts mirror what the
corresponding `flamberge-schemes` decryptor already round-trips in its own unit
tests, so each fixture is faithful to the real container format without embedding
one. Each submodule documents the `docs/DEDRM_SCHEMES.md` section it follows.

Because the fixtures are re-synthesized (not lifted from the schemes' private
`#[cfg(test)]` helpers, which an external test crate cannot see), they live in a
**library** here rather than a `tests/common/` module — that keeps every helper a
`pub` item and so avoids the per-test-binary dead-code warnings that would
otherwise fail the `-D warnings` clippy gate.
