//! KFX-ZIP container: locate the DRMION content member and the DRM voucher
//! member by leading magic (not filename).
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §3.1.  **STUB.**

use crate::{FormatError, Result};

/// DRMION content member prefix (`\xeaDRMION\xee`). Payload is `member[8..len-8]`.
pub const DRMION_MAGIC: &[u8; 8] = b"\xeaDRMION\xee";
/// Amazon ION binary version marker; also the voucher member's leading bytes.
pub const ION_BVM: &[u8; 4] = b"\xe0\x01\x00\xea";
/// ASCII sentinel that identifies the voucher member among ION streams.
pub const VOUCHER_SENTINEL: &[u8] = b"ProtectedData";

#[derive(Debug, Default)]
pub struct KfxZip {
    /// (member name, DRMION payload with the 8-byte prefix/suffix stripped).
    pub drmion_members: Vec<(String, Vec<u8>)>,
    /// Raw voucher member bytes (including the BVM), if found.
    pub voucher: Option<Vec<u8>>,
}

impl KfxZip {
    pub fn parse(_data: &[u8]) -> Result<Self> {
        // TODO(kfx): open the zip, scan members by magic, strip DRMION 8+8,
        // find the voucher member containing `ProtectedData`.
        Err(FormatError::Unimplemented("kfx_zip::parse"))
    }
}
