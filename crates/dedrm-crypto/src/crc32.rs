//! CRC-32 variants used by the PID / key-derivation code.
//!
//! Reflected CRC-32 (IEEE, poly `0xEDB88320`). Two entry points:
//! * [`ieee`] — the standard CRC-32 (init `0xFFFFFFFF`, xorout `0xFFFFFFFF`),
//!   matching Python `binascii.crc32(data)`. Used by eReader's user key.
//! * [`dedrm`] — the `(~binascii.crc32(data, -1)) & 0xFFFFFFFF` variant used by
//!   the Kindle PID helpers, which reduces to CRC-32 with init `0` and no final
//!   XOR.
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §2.5 / §6.5.

const POLY: u32 = 0xEDB8_8320;

fn update(mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ POLY } else { crc >> 1 };
        }
    }
    crc
}

/// Standard IEEE CRC-32 (== Python `binascii.crc32(data)`).
pub fn ieee(data: &[u8]) -> u32 {
    update(0xFFFF_FFFF, data) ^ 0xFFFF_FFFF
}

/// The DeDRM PID CRC-32 (== `(~binascii.crc32(data, -1)) & 0xFFFFFFFF`).
pub fn dedrm(data: &[u8]) -> u32 {
    update(0x0000_0000, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ieee_known_vector() {
        // CRC-32("123456789") == 0xCBF43926
        assert_eq!(ieee(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn dedrm_is_uninverted() {
        // dedrm(x) and ieee(x) differ only by the standard init/xorout folding.
        assert_ne!(dedrm(b"123456789"), ieee(b"123456789"));
    }
}
