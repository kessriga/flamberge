//! Amazon ION binary format — minimal pull parser for KFX voucher/content.
//!
//! Type descriptor byte = high nibble type-id, low nibble length (`0xE` = VarUInt
//! length, `0xF` = null). VarUInt/VarInt are big-endian base-128 with the
//! terminator flagged by a set high bit. A shared symbol table (`ProtectedData`)
//! must be pre-seeded so annotations resolve to names like
//! `com.amazon.drm.Voucher@1.0`.
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §3.2.  **STUB.**

use crate::{FormatError, Result};

pub const BVM: [u8; 4] = [0xE0, 0x01, 0x00, 0xEA];

/// ION type ids (high nibble of the descriptor byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeId {
    Null,
    Bool,
    PosInt,
    NegInt,
    Float,
    Decimal,
    Timestamp,
    Symbol,
    String,
    Clob,
    Blob,
    List,
    Sexp,
    Struct,
    Annotation,
    Unused,
}

impl TypeId {
    pub fn from_nibble(n: u8) -> TypeId {
        match n & 0x0F {
            0x0 => TypeId::Null,
            0x1 => TypeId::Bool,
            0x2 => TypeId::PosInt,
            0x3 => TypeId::NegInt,
            0x4 => TypeId::Float,
            0x5 => TypeId::Decimal,
            0x6 => TypeId::Timestamp,
            0x7 => TypeId::Symbol,
            0x8 => TypeId::String,
            0x9 => TypeId::Clob,
            0xA => TypeId::Blob,
            0xB => TypeId::List,
            0xC => TypeId::Sexp,
            0xD => TypeId::Struct,
            0xE => TypeId::Annotation,
            _ => TypeId::Unused,
        }
    }
}

/// Read an ION VarUInt: continue while the high bit is clear; the byte with the
/// high bit set terminates. Returns `(value, bytes_consumed)`.  **STUB.**
pub fn read_varuint(_data: &[u8]) -> Result<(u64, usize)> {
    Err(FormatError::Unimplemented("ion::read_varuint"))
}

/// The fixed `ProtectedData` shared symbol table (SIDs start at 11). See
/// `ion.py::SYM_NAMES` — order is load-bearing.  **STUB.**
pub fn protected_data_symbols() -> Vec<&'static str> {
    // TODO(ion): port the full ordered SYM_NAMES list (§3.2).
    Vec::new()
}
