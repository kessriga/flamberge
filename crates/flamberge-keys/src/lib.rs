//! Key acquisition for the DeDRM schemes.
//!
//! Two kinds of key source, mirroring the Python tools:
//! * **Offline generators** (pure crypto, reproducible anywhere): PID encoders
//!   (`pid`), B&N name+CC keygen (`ignoble`), eReader name+CC key (`ereader`),
//!   Kobo device-key derivation (`kobo`). These are implemented.
//! * **Platform extraction** (reads local DRM-app state — registry/DPAPI,
//!   plists, SQLite): `kindle`, `adobe`. These are stubbed and are the parts
//!   that require a specific host OS + user profile.
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §2.5, §4, §6, §7.2, §8.2, §9.2.

pub mod adobe;
pub mod ereader;
pub mod error;
pub mod ignoble;
pub mod kindle;
pub mod kobo;
pub mod pid;

pub use error::KeyError;

pub type Result<T> = std::result::Result<T, KeyError>;

/// All candidate keys gathered for a decryption attempt. Schemes brute-force the
/// relevant bucket against the book. Mirrors the plugin's prefs buckets.
#[derive(Debug, Default, Clone)]
pub struct KeyStore {
    /// Explicit Mobipocket/Topaz/KFX PIDs (8- or 10-char).
    pub pids: Vec<String>,
    /// Kindle device serial numbers (eInk / android-derived).
    pub serials: Vec<String>,
    /// Adobe ADEPT user keys: DER-encoded RSA private keys.
    pub adept_keys: Vec<Vec<u8>>,
    /// Barnes & Noble user keys (28-char base64 `ccHash`).
    pub bandn_keys: Vec<String>,
    /// eReader user keys (8-byte DES keys, hex in the plugin prefs).
    pub ereader_keys: Vec<[u8; 8]>,
    /// Kobo candidate user keys (16-byte AES keys).
    pub kobo_keys: Vec<[u8; 16]>,
}

impl KeyStore {
    pub fn new() -> Self {
        Self::default()
    }
}
