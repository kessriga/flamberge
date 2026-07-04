//! Shared `.kinf` obfuscation primitives (§6.1).
//!
//! Amazon's `.kinf` files layer three things on top of the real crypto: a
//! substitution codec (`encode`/`decode` over 64-byte character maps), a
//! prime-based byte rotation, and MD5 key-name hashing. These are anti-tamper,
//! not security — but they must be reproduced byte-for-byte or the AES/PBKDF2
//! layer underneath decrypts to garbage.
//!
//! The character maps differ between the Kindle-for-PC and Kindle-for-Mac
//! builds; [`Platform`] selects the right pair. `encode`/`encode_hash` are
//! identical to the PID codec and are re-used from [`crate::pid`].

pub use crate::pid::{encode, encode_hash};

/// Shared 32-char header/PID map (`charMap1` on Mac, `testMap1` on PC — same
/// bytes). Used to decode the `.kinf` header blob and by `getK4Pids`.
pub const CHARMAP1: &[u8] = crate::pid::CHARMAP1;

/// Shared value-framing map (`testMap8`), identical on PC and Mac. Applied after
/// the prime rotation to recover the DPAPI/GCM ciphertext of a key record.
pub const TESTMAP8: &[u8] = b"YvaZ3FfUm9Nn_c1XuG4yCAzB0beVg-TtHh5SsIiR6rJjQdW2wEq7KkPpL8lOoMxD";

/// Kindle-for-PC `charMap5` (rcnt framing + `.kinf2018` password/value codec).
pub const CHARMAP5_PC: &[u8] = b"AzB0bYyCeVvaZ3FfUuG4g-TtHh5SsIiR6rJjQq7KkPpL8lOoMm9Nn_c1XxDdW2wE";
/// Kindle-for-PC `charMap2` (unused offline: PC v5 goes through Windows DPAPI).
pub const CHARMAP2_PC: &[u8] = b"AaZzB0bYyCc1XxDdW2wEeVv3FfUuG4g-TtHh5SsIiR6rJjQq7KkPpL8lOoMm9Nn_";
/// Kindle-for-Mac `charMap2` (v5 emulated-DPAPI password/value codec). The Mac
/// build re-uses this same table as its `charMap5`.
pub const CHARMAP2_MAC: &[u8] = b"ZB0bYyc1xDdW2wEV3Ff7KkPpL8UuGA4gz-Tme9Nn_tHh5SvXCsIiR6rJjQaqlOoM";

/// Which Kindle desktop build produced the `.kinf` file. Selects the char maps
/// and the v5 key-derivation path (§6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Kindle for PC (`kindlekey.py` Windows branch).
    Pc,
    /// Kindle for Mac (`kindlekey.py` macOS branch).
    Mac,
}

impl Platform {
    /// `charMap5`: rcnt framing decode and the `.kinf2018` password/value codec.
    pub fn charmap5(self) -> &'static [u8] {
        match self {
            Platform::Pc => CHARMAP5_PC,
            // Mac re-uses charMap2 as charMap5 (kindlekey.py: `charMap5 = charMap2`).
            Platform::Mac => CHARMAP2_MAC,
        }
    }

    /// `charMap2`: the Mac v5 emulated-DPAPI password/value codec.
    pub fn charmap2(self) -> &'static [u8] {
        match self {
            Platform::Pc => CHARMAP2_PC,
            Platform::Mac => CHARMAP2_MAC,
        }
    }
}

/// `decode(data, map)` — inverse of [`encode`]. Each pair of input symbols maps
/// back to one byte: `value = ((high * len ^ 0x80) & 0xFF) + low`. Stops early
/// (matching the Python) at the first symbol not present in `map`.
pub fn decode(data: &[u8], map: &[u8]) -> Vec<u8> {
    let n = map.len();
    let mut out = Vec::with_capacity(data.len() / 2);
    let mut i = 0;
    while i + 1 < data.len() {
        let (Some(high), Some(low)) = (
            map.iter().position(|&c| c == data[i]),
            map.iter().position(|&c| c == data[i + 1]),
        ) else {
            break;
        };
        let value = (((high * n) ^ 0x80) & 0xFF) + low;
        out.push(value as u8);
        i += 2;
    }
    out
}

/// Largest prime ≤ `n` (`primes(n)[-1]` in the Python). Returns `None` for
/// `n < 2`. Used only to compute the record rotation offset (§6.2).
pub fn largest_prime(n: usize) -> Option<usize> {
    if n < 2 {
        return None;
    }
    let mut largest = 2;
    let mut candidate = 3;
    while candidate <= n {
        if (2..candidate).all(|d| candidate % d != 0) {
            largest = candidate;
        }
        candidate += 2;
    }
    Some(largest)
}

/// Undo the record rotation: the encoder moved the first `noffset` bytes to the
/// end, where `noffset = len - largest_prime(len/3)`. Rotating the tail back to
/// the front realigns the data for [`decode`] with [`TESTMAP8`] (§6.2).
pub fn derotate(encdata: &[u8]) -> Vec<u8> {
    let contlen = encdata.len();
    let Some(prime) = largest_prime(contlen / 3) else {
        return encdata.to_vec();
    };
    let noffset = contlen - prime;
    let mut out = Vec::with_capacity(contlen);
    out.extend_from_slice(&encdata[noffset..]);
    out.extend_from_slice(&encdata[..noffset]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trips_all_maps() {
        let data: Vec<u8> = (0u16..=255).map(|b| b as u8).collect();
        for map in [CHARMAP1, TESTMAP8, CHARMAP5_PC, CHARMAP2_PC, CHARMAP2_MAC] {
            let encoded = encode(&data, map);
            assert_eq!(encoded.len(), data.len() * 2);
            assert_eq!(decode(&encoded, map), data, "round-trip failed for a map");
        }
    }

    #[test]
    fn char_maps_are_64_bytes_and_unique() {
        for map in [TESTMAP8, CHARMAP5_PC, CHARMAP2_PC, CHARMAP2_MAC] {
            assert_eq!(map.len(), 64);
            let mut sorted = map.to_vec();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(sorted.len(), 64, "map has duplicate symbols");
        }
        assert_eq!(CHARMAP1.len(), 32);
    }

    #[test]
    fn largest_prime_matches_reference() {
        assert_eq!(largest_prime(0), None);
        assert_eq!(largest_prime(1), None);
        assert_eq!(largest_prime(2), Some(2));
        assert_eq!(largest_prime(3), Some(3));
        assert_eq!(largest_prime(10), Some(7));
        assert_eq!(largest_prime(11), Some(11));
        assert_eq!(largest_prime(100), Some(97));
    }

    #[test]
    fn derotate_inverts_the_encoder_rotation() {
        // `derotate` is the ported transform: a left-rotation by `noffset`
        // (`encdata[noffset:] + encdata[:noffset]`). Build the on-disk bytes by
        // the inverse (right-rotation) so that `derotate` recovers the aligned
        // data.
        for len in [7usize, 16, 33, 64, 129] {
            let aligned: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let prime = largest_prime(len / 3).unwrap();
            let noffset = len - prime;
            let split = len - noffset;
            let mut on_disk = Vec::new();
            on_disk.extend_from_slice(&aligned[split..]);
            on_disk.extend_from_slice(&aligned[..split]);
            assert_eq!(derotate(&on_disk), aligned, "derotate failed at len {len}");
        }
    }

    #[test]
    fn platform_selects_distinct_maps() {
        assert_eq!(Platform::Pc.charmap5(), CHARMAP5_PC);
        assert_eq!(Platform::Mac.charmap5(), CHARMAP2_MAC);
        assert_eq!(Platform::Mac.charmap2(), CHARMAP2_MAC);
        assert_ne!(Platform::Pc.charmap5(), Platform::Mac.charmap5());
    }
}
