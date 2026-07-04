//! Cross-scheme integration-test support for Flamberge.
//!
//! This crate exists only to host the workspace-level end-to-end suite. It is a
//! library (not `#[cfg(test)]` helpers inside a scheme crate) for two reasons:
//!
//! * An integration test in a `tests/` directory compiles as its own crate that
//!   links the crate-under-test **externally**, so it cannot see any scheme's
//!   `#[cfg(test)]` fixture builders. The fixtures therefore have to be
//!   re-synthesized from public APIs, and a shared library is the natural home.
//! * Placing the fixtures in a `tests/common/mod.rs` shared module would make
//!   each test binary flag the builders it happens not to call as dead code,
//!   which the workspace's `-D warnings` clippy gate turns fatal. Public library
//!   items are exempt from that, so the suite stays warning-clean.
//!
//! The actual tests live in `tests/schemes.rs`; the [`fixtures`] module holds the
//! synthesized encrypted books. Nothing here ships in a release build — the crate
//! is `publish = false` and is only compiled by `cargo test` / `cargo clippy`.

pub mod fixtures;
