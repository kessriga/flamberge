//! eReader DRM header (record 1 "cookie") parsing — key-independent.
//!
//! Record 1's first 8 bytes are a DES key that decrypts the cookie trailer at
//! the *end* of the same record, yielding `(cookie_shuf, cookie_size)`; the last
//! `cookie_size` bytes decrypt and unshuffle into the header `r`. None of this
//! uses the buyer's name+CC key — that only unwraps the content key later
//! (§8.3). Reference: `docs/DEDRM_SCHEMES.md` §8.3 (`erdr2pml.py`
//! `EreaderProcessor.__init__`).

use flamberge_crypto::des;
use flamberge_formats::FormatError;

use crate::{Result, SchemeError};

/// Required flag bits (7, 9, 10) that a supported eReader file must set.
const REQD_FLAGS: u32 = (1 << 9) | (1 << 7) | (1 << 10);

/// The decoded, key-independent DRM header for one eReader book.
pub(super) struct Header {
    pub num_text_pages: usize,
    pub first_image_page: usize,
    pub num_image_pages: usize,
    pub first_footnote_page: usize,
    pub num_footnote_pages: usize,
    pub first_sidebar_page: usize,
    pub num_sidebar_pages: usize,
    /// XOR table (v272 only) used to de-obfuscate footnote/sidebar id records.
    pub xortable: Vec<u8>,
    /// Book (`content_key`) ciphertext, unwrapped by the user key (§8.3).
    pub encrypted_key: [u8; 8],
    /// `SHA1(content_key)` — validates a recovered key against this book.
    pub encrypted_key_sha: [u8; 20],
}

fn invalid(msg: impl Into<String>) -> SchemeError {
    SchemeError::Format(FormatError::Invalid(msg.into()))
}

fn be16(buf: &[u8], off: usize) -> Result<u16> {
    buf.get(off..off + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .ok_or_else(|| invalid("eReader header truncated"))
}

fn be32(buf: &[u8], off: usize) -> Result<u32> {
    buf.get(off..off + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| invalid("eReader header truncated"))
}

/// Reverse `erdr2pml.py`'s `unshuff`: `r[j] = data[i]` where `j` advances by
/// `shuf` (mod length) each step. Positions never landed on stay zero, exactly
/// as in the original scatter.
fn unshuff(data: &[u8], shuf: u32) -> Vec<u8> {
    let n = data.len();
    let mut out = vec![0u8; n];
    if n == 0 {
        return out;
    }
    let shuf = shuf as usize;
    let mut j = 0usize;
    for &byte in data {
        j = (j + shuf) % n;
        out[j] = byte;
    }
    out
}

/// Parse the DRM header from record 0 (version) and record 1 (cookie). Returns
/// [`SchemeError::NotThisScheme`] is *not* produced here — an unrecognised
/// container is rejected by the caller; a bad version/cookie is a terminal
/// structural error for a file that already looks like eReader DRM.
pub(super) fn parse(record0: &[u8], record1: &[u8], is_book: bool) -> Result<Header> {
    let version = be16(record0, 0)?;
    if version != 259 && version != 260 && version != 272 {
        return Err(invalid(format!("unsupported eReader version {version}")));
    }

    let data = record1;
    if data.len() < 16 {
        return Err(invalid("eReader record 1 too short"));
    }

    // The cookie key is derived from record 1's own first block.
    let cookie_key = des::fix_key(&data[0..8]);
    let trailer = des::ecb_decrypt(&cookie_key, &data[data.len() - 8..])?;
    let cookie_shuf = u32::from_be_bytes(trailer[0..4].try_into().unwrap());
    let cookie_size = u32::from_be_bytes(trailer[4..8].try_into().unwrap()) as usize;
    if !(3..=0x14).contains(&cookie_shuf) || !(0xf0..=0x200).contains(&cookie_size) {
        return Err(invalid("eReader cookie shuffle/size out of range"));
    }
    if cookie_size > data.len() {
        return Err(invalid("eReader cookie larger than record 1"));
    }

    let input = des::ecb_decrypt(&cookie_key, &data[data.len() - cookie_size..])?;
    // The last 8 bytes of `input` are the (shuf, size) trailer; the header is
    // the shuffled remainder.
    let r = unshuff(&input[..input.len() - 8], cookie_shuf);

    let drm_sub_version = be16(&r, 0)?;
    let num_text_pages = be16(&r, 2)?.saturating_sub(1) as usize;
    let flags = be32(&r, 4)?;
    if flags & REQD_FLAGS != REQD_FLAGS {
        return Err(invalid(format!(
            "incompatible eReader file (flags {flags:#x})"
        )));
    }
    let first_image_page = be16(&r, 24)? as usize;
    let num_image_pages = be16(&r, 26)? as usize;

    let mut header = Header {
        num_text_pages,
        first_image_page,
        num_image_pages,
        first_footnote_page: 0,
        num_footnote_pages: 0,
        first_sidebar_page: 0,
        num_sidebar_pages: 0,
        xortable: Vec::new(),
        encrypted_key: [0u8; 8],
        encrypted_key_sha: [0u8; 20],
    };

    if version == 272 {
        header.first_footnote_page = be16(&r, 44)? as usize;
        header.num_footnote_pages = be16(&r, 46)? as usize;
        if is_book {
            header.first_sidebar_page = be16(&r, 36)? as usize;
            header.num_sidebar_pages = be16(&r, 38)? as usize;
        }
        // The XOR table is sliced from the *raw, still-shuffled* record 1, not
        // from `r` (it predates decryption/unshuffle).
        let xortable_offset = be16(&r, 40)? as usize;
        let xortable_size = be16(&r, 42)? as usize;
        header.xortable = data
            .get(xortable_offset..xortable_offset + xortable_size)
            .unwrap_or_default()
            .to_vec();
    }

    let (key_off, sha_off) = key_offsets(version, drm_sub_version)?;
    header.encrypted_key = r
        .get(key_off..key_off + 8)
        .ok_or_else(|| invalid("eReader encrypted key truncated"))?
        .try_into()
        .unwrap();
    header.encrypted_key_sha = r
        .get(sha_off..sha_off + 20)
        .ok_or_else(|| invalid("eReader key digest truncated"))?
        .try_into()
        .unwrap();

    Ok(header)
}

/// Version-dependent `(encrypted_key, encrypted_key_sha)` byte offsets within
/// the header `r` (§8.3).
fn key_offsets(version: u16, drm_sub_version: u16) -> Result<(usize, usize)> {
    match version {
        259 if drm_sub_version == 7 => Ok((64, 44)),
        260 if drm_sub_version == 13 => Ok((44, 52)),
        260 if drm_sub_version == 11 => Ok((64, 44)),
        272 => Ok((172, 56)),
        _ => Err(invalid(format!(
            "unsupported eReader DRM sub-version {drm_sub_version} (v{version})"
        ))),
    }
}
