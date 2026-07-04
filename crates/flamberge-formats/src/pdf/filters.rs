//! Stream decoding: the `FlateDecode` / `LZWDecode` / `ASCII85Decode` filters
//! and the TIFF/PNG predictors, exposed as [`PdfStream::decoded`].
//!
//! Decoding assumes the raw bytes are already decrypted — decryption happens in
//! the scheme layer (TASK-12) before filters are applied.

use super::object::{Dict, Object, PdfStream};
use crate::{FormatError, Result};
use std::io::Read;

impl PdfStream {
    /// The filter list for this stream (`/Filter` may be a name or an array).
    fn filters(&self) -> Vec<String> {
        match self.dict.get("Filter") {
            Some(Object::Name(n)) => vec![n.clone()],
            Some(Object::Array(a)) => a
                .iter()
                .filter_map(|o| o.as_name().map(str::to_owned))
                .collect(),
            _ => Vec::new(),
        }
    }

    /// The per-filter `/DecodeParms` (or legacy `/DP`) list, aligned 1:1 with
    /// [`Self::filters`].
    ///
    /// `/DecodeParms` is a single dict when `/Filter` is a single name, or an
    /// array (of dicts / nulls) parallel to a `/Filter` array. Either form maps
    /// onto a per-filter slot so the predictor is applied only to its owning
    /// filter's output — never to the whole chain.
    fn decode_parms(&self, nfilters: usize) -> Vec<Option<Dict>> {
        let mut out = vec![None; nfilters];
        match self.dict.get("DP").or_else(|| self.dict.get("DecodeParms")) {
            Some(Object::Dict(d)) => {
                if let Some(slot) = out.first_mut() {
                    *slot = Some(d.clone());
                }
            }
            Some(Object::Array(a)) => {
                for (slot, item) in out.iter_mut().zip(a) {
                    if let Object::Dict(d) = item {
                        *slot = Some(d.clone());
                    }
                }
            }
            _ => {}
        }
        out
    }

    /// Decode the raw stream body: apply each filter and, if that filter
    /// declares one, its predictor.
    ///
    /// Names `Fl`/`LZW`/`A85` are accepted as abbreviations, matching
    /// `ineptpdf.py`.
    pub fn decoded(&self) -> Result<Vec<u8>> {
        let filters = self.filters();
        let parms = self.decode_parms(filters.len());
        let mut data = self.rawdata.clone();
        for (f, params) in filters.iter().zip(&parms) {
            data = match f.as_str() {
                "FlateDecode" | "Fl" => flate_decode(&data)?,
                "LZWDecode" | "LZW" => lzw_decode(&data)?,
                "ASCII85Decode" | "A85" => ascii85_decode(&data),
                "Crypt" => {
                    return Err(FormatError::Unimplemented("pdf: /Crypt filter"));
                }
                other => {
                    return Err(FormatError::Invalid(format!(
                        "pdf: unsupported filter {}",
                        other
                    )));
                }
            };
            if let Some(params) = params {
                if let Some(pred) = params.get("Predictor").and_then(Object::as_int) {
                    if pred >= 2 {
                        data = apply_predictor(pred, params, &data)?;
                    }
                }
            }
        }
        Ok(data)
    }
}

/// FlateDecode = zlib-wrapped DEFLATE.
fn flate_decode(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::ZlibDecoder::new(data)
        .read_to_end(&mut out)
        .map_err(|e| FormatError::Invalid(format!("pdf: FlateDecode failed: {}", e)))?;
    Ok(out)
}

/// ASCII85 decode (`~` terminated). Faithful to `ineptpdf.ascii85decode`:
/// whitespace is ignored, `z` expands to four zero bytes.
fn ascii85_decode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut group = [0u8; 5];
    let mut n = 0usize;
    for &c in data {
        match c {
            b'~' => break,
            b'z' if n == 0 => out.extend_from_slice(&[0, 0, 0, 0]),
            b'!'..=b'u' => {
                group[n] = c - 33;
                n += 1;
                if n == 5 {
                    let mut val = 0u32;
                    for &g in &group {
                        val = val.wrapping_mul(85).wrapping_add(g as u32);
                    }
                    out.extend_from_slice(&val.to_be_bytes());
                    n = 0;
                }
            }
            _ => { /* ignore whitespace and stray bytes */ }
        }
    }
    if n > 0 {
        // Pad the final partial group with 'u' (84) and emit n-1 bytes.
        let mut val = 0u32;
        for (i, &g) in group.iter().enumerate() {
            let g = if i < n { g as u32 } else { 84 };
            val = val.wrapping_mul(85).wrapping_add(g);
        }
        let bytes = val.to_be_bytes();
        out.extend_from_slice(&bytes[..n - 1]);
    }
    out
}

/// PDF LZWDecode: variable-width codes (9–12 bits), MSB-first, with the default
/// EarlyChange = 1 (code width bumps one code before the table is full).
fn lzw_decode(data: &[u8]) -> Result<Vec<u8>> {
    const CLEAR: u32 = 256;
    const EOD: u32 = 257;

    let mut out = Vec::new();
    let mut table: Vec<Vec<u8>> = Vec::new();
    let reset = |t: &mut Vec<Vec<u8>>| {
        t.clear();
        for b in 0u16..256 {
            t.push(vec![b as u8]);
        }
        t.push(Vec::new()); // 256 CLEAR (placeholder)
        t.push(Vec::new()); // 257 EOD (placeholder)
    };
    reset(&mut table);

    let mut code_width = 9u32;
    let mut prev: Option<u32> = None;

    let mut bitbuf = 0u32;
    let mut bitcnt = 0u32;
    let mut idx = 0usize;

    loop {
        // Refill the bit buffer until we have a full code.
        while bitcnt < code_width {
            let byte = match data.get(idx) {
                Some(&b) => b,
                None => return Ok(out), // ran out of input
            };
            idx += 1;
            bitbuf = bitbuf << 8 | byte as u32;
            bitcnt += 8;
        }
        bitcnt -= code_width;
        let code = (bitbuf >> bitcnt) & ((1 << code_width) - 1);

        if code == EOD {
            break;
        }
        if code == CLEAR {
            reset(&mut table);
            code_width = 9;
            prev = None;
            continue;
        }

        let entry: Vec<u8> = if (code as usize) < table.len() {
            table[code as usize].clone()
        } else if code as usize == table.len() {
            // KwKwK case: entry = prev + prev[0].
            match prev {
                Some(p) => {
                    let mut e = table[p as usize].clone();
                    if let Some(&first) = e.first() {
                        e.push(first);
                    }
                    e
                }
                None => {
                    return Err(FormatError::Invalid("pdf: LZW code before any data".into()));
                }
            }
        } else {
            return Err(FormatError::Invalid(format!(
                "pdf: invalid LZW code {}",
                code
            )));
        };
        out.extend_from_slice(&entry);

        if let Some(p) = prev {
            let mut new_entry = table[p as usize].clone();
            new_entry.push(entry[0]);
            table.push(new_entry);
        }
        prev = Some(code);

        // EarlyChange = 1: widen one code early.
        let size = table.len();
        if size + 1 >= (1 << code_width) && code_width < 12 {
            code_width += 1;
        }
    }
    Ok(out)
}

/// Apply a stream predictor to `data`. Supports Predictor 2 (TIFF, 8-bit) and
/// the PNG family (10–15). `docs/DEDRM_SCHEMES.md` §7.4 only requires PNG-up
/// (Predictor 12) for xref streams; the full PNG row-filter set is handled for
/// correctness.
fn apply_predictor(predictor: i64, params: &Dict, data: &[u8]) -> Result<Vec<u8>> {
    let columns = params
        .get("Columns")
        .and_then(Object::as_int)
        .unwrap_or(1)
        .max(1) as usize;
    let colors = params
        .get("Colors")
        .and_then(Object::as_int)
        .unwrap_or(1)
        .max(1) as usize;
    let bpc = params
        .get("BitsPerComponent")
        .and_then(Object::as_int)
        .unwrap_or(8)
        .max(1) as usize;
    let bpp = (colors * bpc).div_ceil(8).max(1);
    let rowlen = (columns * colors * bpc).div_ceil(8);
    if rowlen == 0 {
        return Ok(data.to_vec());
    }

    if predictor == 2 {
        // TIFF Predictor 2: horizontal differencing (only 8-bit supported).
        if bpc != 8 {
            return Err(FormatError::Unimplemented(
                "pdf: TIFF predictor with non-8-bit samples",
            ));
        }
        let mut out = data.to_vec();
        for row in out.chunks_mut(rowlen) {
            for i in bpp..row.len() {
                row[i] = row[i].wrapping_add(row[i - bpp]);
            }
        }
        return Ok(out);
    }

    // PNG predictors: each row is prefixed by a filter-type byte.
    let stride = rowlen + 1;
    let mut out = Vec::with_capacity(data.len());
    let mut prev_row = vec![0u8; rowlen];
    let mut i = 0;
    while i < data.len() {
        let ftype = data[i];
        let avail = (data.len() - (i + 1)).min(rowlen);
        let mut row = data[i + 1..i + 1 + avail].to_vec();
        row.resize(rowlen, 0);
        png_unfilter(ftype, bpp, &prev_row, &mut row)?;
        out.extend_from_slice(&row);
        prev_row = row;
        i += stride;
    }
    Ok(out)
}

/// Reverse one PNG row filter in place. `prev` is the already-reconstructed row
/// above; `row` holds the raw filtered bytes on entry, reconstructed on exit.
fn png_unfilter(ftype: u8, bpp: usize, prev: &[u8], row: &mut [u8]) -> Result<()> {
    match ftype {
        0 => {} // None
        1 => {
            // Sub: add the byte `bpp` to the left.
            for i in bpp..row.len() {
                row[i] = row[i].wrapping_add(row[i - bpp]);
            }
        }
        2 => {
            // Up: add the byte above.
            for i in 0..row.len() {
                row[i] = row[i].wrapping_add(prev[i]);
            }
        }
        3 => {
            // Average: add floor((left + up) / 2).
            for i in 0..row.len() {
                let left = if i >= bpp { row[i - bpp] as u16 } else { 0 };
                let up = prev[i] as u16;
                row[i] = row[i].wrapping_add(((left + up) / 2) as u8);
            }
        }
        4 => {
            // Paeth.
            for i in 0..row.len() {
                let a = if i >= bpp { row[i - bpp] as i16 } else { 0 };
                let b = prev[i] as i16;
                let c = if i >= bpp { prev[i - bpp] as i16 } else { 0 };
                let p = a + b - c;
                let pa = (p - a).abs();
                let pb = (p - b).abs();
                let pc = (p - c).abs();
                let pred = if pa <= pb && pa <= pc {
                    a
                } else if pb <= pc {
                    b
                } else {
                    c
                };
                row[i] = row[i].wrapping_add(pred as u8);
            }
        }
        other => {
            return Err(FormatError::Invalid(format!(
                "pdf: unknown PNG filter type {}",
                other
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn ascii85_roundtrip_known() {
        // "Man " encodes to "9jqo^" in ASCII85.
        let decoded = ascii85_decode(b"9jqo^~>");
        assert_eq!(decoded, b"Man ");
    }

    #[test]
    fn lzw_decode_pdf_spec_example() {
        // Example from the PDF spec (§7.4.4.2): the encoded stream
        // 80 0B 60 50 22 0C 0C 85 01 decodes to the 10 bytes "-----A---B"
        // (2D 2D 2D 2D 2D 41 2D 2D 2D 42), exercising CLEAR, the KwKwK case,
        // and EarlyChange.
        let encoded = [0x80u8, 0x0B, 0x60, 0x50, 0x22, 0x0C, 0x0C, 0x85, 0x01];
        let decoded = lzw_decode(&encoded).unwrap();
        assert_eq!(
            decoded,
            vec![0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x41, 0x2D, 0x2D, 0x2D, 0x42]
        );
    }

    #[test]
    fn predictor_12_png_up() {
        // Two rows of 3 columns, PNG-Up (filter byte 2). Row0 delta from zeros,
        // row1 delta from row0 → both reconstruct to [10,20,30].
        let params: Dict = [
            ("Predictor".to_string(), Object::Int(12)),
            ("Columns".to_string(), Object::Int(3)),
        ]
        .into_iter()
        .collect();
        let filtered = [2u8, 10, 20, 30, 2, 0, 0, 0];
        let out = apply_predictor(12, &params, &filtered).unwrap();
        assert_eq!(out, vec![10, 20, 30, 10, 20, 30]);
    }

    #[test]
    fn flate_stream_decode() {
        let plain = b"the quick brown fox";
        let comp = zlib(plain);
        let dict: Dict = [
            ("Length".to_string(), Object::Int(comp.len() as i64)),
            ("Filter".to_string(), Object::Name("FlateDecode".into())),
        ]
        .into_iter()
        .collect();
        let stream = PdfStream {
            dict,
            rawdata: comp,
            objid: 5,
            genno: 0,
        };
        assert_eq!(stream.decoded().unwrap(), plain);
    }

    #[test]
    fn array_form_decode_parms_applies_predictor() {
        // `/Filter [/FlateDecode] /DecodeParms [<< /Predictor 12 /Columns 3 >>]`
        // — the array form must still reverse the PNG-up predictor, not skip it.
        let filtered = [2u8, 10, 20, 30, 2, 0, 0, 0]; // two PNG-Up rows
        let comp = zlib(&filtered);
        let parms: Dict = [
            ("Predictor".to_string(), Object::Int(12)),
            ("Columns".to_string(), Object::Int(3)),
        ]
        .into_iter()
        .collect();
        let dict: Dict = [
            ("Length".to_string(), Object::Int(comp.len() as i64)),
            (
                "Filter".to_string(),
                Object::Array(vec![Object::Name("FlateDecode".into())]),
            ),
            (
                "DecodeParms".to_string(),
                Object::Array(vec![Object::Dict(parms)]),
            ),
        ]
        .into_iter()
        .collect();
        let stream = PdfStream {
            dict,
            rawdata: comp,
            objid: 7,
            genno: 0,
        };
        assert_eq!(stream.decoded().unwrap(), vec![10, 20, 30, 10, 20, 30]);
    }
}
