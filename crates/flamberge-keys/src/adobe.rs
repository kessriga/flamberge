//! Adobe ADEPT user-key extraction (the RSA private key DER, "adobekey.der").
//!
//! Windows path needs DPAPI (`CryptUnprotectData`) over a machine-bound 32-byte
//! entropy (volume serial + CPUID vendor/signature + username) to recover the
//! `keykey`, then AES-CBC to decrypt `privateLicenseKey`. macOS reads
//! `activation.dat` and strips a 26-byte header. Both are **stubbed** here.
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §7.2.

use crate::{KeyError, Result};

/// The fixed header length stripped from the decoded license blob (both OSes).
pub const HEADER_STRIP_LEN: usize = 26;

/// Extract Adobe ADEPT user keys (DER RSA private keys) from the local ADE
/// installation.  **STUB** (platform-specific: Windows DPAPI / macOS plist).
pub fn extract_keys() -> Result<Vec<Vec<u8>>> {
    Err(KeyError::Unimplemented("adobe::extract_keys"))
}
