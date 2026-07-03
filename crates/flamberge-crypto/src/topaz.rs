//! Topaz stream cipher (Amazon Kindle Topaz format).
//!
//! Two 32-bit state words with wrapping arithmetic. The state update feeds back
//! the *plaintext* byte, so the cipher is self-synchronizing. There is no IV and
//! no block structure: state is re-derived from the key for every record.
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §1.3 / §5.3 (`alfcrypto_src.zip::topaz.c`).

const SEED: u32 = 0xCAFF_E19E;
const MULT: u32 = 0x0F90_2007;

/// A keyed Topaz cipher context. Initialize once per key (per record).
#[derive(Clone, Copy, Debug)]
pub struct TopazCipher {
    v0: u32,
    v1: u32,
}

impl TopazCipher {
    /// Run the key schedule over `key` (typically an 8-byte PID or book key).
    pub fn new(key: &[u8]) -> Self {
        let mut v0 = SEED;
        let mut v1 = 0u32;
        for &k in key {
            v1 = v0;
            let k = k as u32;
            v0 = (v0 >> 2).wrapping_mul(v0 >> 7) ^ k.wrapping_mul(k).wrapping_mul(MULT);
        }
        TopazCipher { v0, v1 }
    }

    /// Decrypt `data` in place-returning form. Advances internal state.
    pub fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        for &c in data {
            let m = c ^ (self.v0 >> 3) as u8 ^ (self.v1 << 3) as u8;
            self.step(m);
            out.push(m);
        }
        out
    }

    /// Encrypt `data`. Present for round-trip testing; the tool only decrypts.
    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        for &p in data {
            let c = p ^ (self.v0 >> 3) as u8 ^ (self.v1 << 3) as u8;
            // Feedback uses the plaintext byte `p` in both directions.
            self.step(p);
            out.push(c);
        }
        out
    }

    #[inline]
    fn step(&mut self, plaintext_byte: u8) {
        let m = plaintext_byte as u32;
        self.v1 = self.v0;
        self.v0 = (self.v0 >> 2).wrapping_mul(self.v0 >> 7) ^ m.wrapping_mul(m).wrapping_mul(MULT);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = b"\x01\x02\x03\x04\x05\x06\x07\x08";
        let plain = b"Topaz scanned-book content record.";
        let ct = TopazCipher::new(key).encrypt(plain);
        assert_ne!(&ct[..], &plain[..]);
        let pt = TopazCipher::new(key).decrypt(&ct);
        assert_eq!(&pt[..], &plain[..]);
    }
}
