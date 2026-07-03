//! RC4 / ARC4 stream cipher (Adobe & B&N PDF per-object decryption).
//!
//! Hand-rolled to avoid a dependency; RC4 is trivial and self-inverse.
//! Reference: `docs/DEDRM_SCHEMES.md` §4.5 / §7.4.

/// Apply RC4 with `key` to `data` (encryption and decryption are identical).
pub fn apply(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: [u8; 256] = std::array::from_fn(|i| i as u8);
    let mut j = 0u8;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }

    let mut out = Vec::with_capacity(data.len());
    let (mut i, mut j) = (0u8, 0u8);
    for &b in data {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
        out.push(b ^ k);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector() {
        // RFC 6229 / classic: RC4("Key", "Plaintext") = BBF316E8D940AF0AD3
        let ct = apply(b"Key", b"Plaintext");
        assert_eq!(hex::encode_upper(&ct), "BBF316E8D940AF0AD3");
        assert_eq!(apply(b"Key", &ct), b"Plaintext");
    }
}
