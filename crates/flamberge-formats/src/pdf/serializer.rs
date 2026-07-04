//! [`PdfSerializer`]: re-emit a [`PdfDocument`] as a clean, unencrypted PDF.
//!
//! Mirrors `ineptpdf.PDFSerializer` in its default (classic-xref) mode:
//! generation numbers are forced to 0, `/Encrypt` is dropped, object streams
//! are dissolved (their members promoted to top-level objects and the container
//! replaced by a harmless placeholder), and a fresh classic `xref` table +
//! trailer are written.

use super::document::PdfDocument;
use super::object::{Dict, Object};
use crate::Result;
use std::collections::HashMap;

/// Re-emits a `PdfDocument` as a clean, unencrypted PDF.
pub struct PdfSerializer<'a> {
    doc: &'a PdfDocument,
}

impl<'a> PdfSerializer<'a> {
    pub fn new(doc: &'a PdfDocument) -> Self {
        PdfSerializer { doc }
    }

    /// Serialize the document to bytes.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        // Header: the original `%PDF-x.y` plus a binary marker comment.
        out.extend_from_slice(&self.doc.version);
        out.extend_from_slice(b"\n%\xe2\xe3\xcf\xd3\n");

        // Object ids to emit, minus the /Encrypt object if it is indirect.
        let mut ids = self.doc.object_ids();
        let encrypt_objid = match self.doc.trailer.get("Encrypt") {
            Some(Object::Ref(objid, _)) => Some(*objid),
            _ => None,
        };
        if let Some(eid) = encrypt_objid {
            ids.retain(|&id| id != eid);
        }

        let maxobj = ids.iter().copied().max().unwrap_or(0);
        let mut offsets: HashMap<u32, usize> = HashMap::new();

        for &objid in &ids {
            let obj = match self.doc.get_object(objid) {
                Ok(o) => o,
                Err(_) => continue, // skip unreadable/free entries
            };
            // Drop cross-reference streams entirely; a fresh classic table
            // replaces them.
            if obj.type_name() == Some("XRef") {
                continue;
            }
            offsets.insert(objid, out.len());
            out.extend_from_slice(format!("{} 0 obj", objid).as_bytes());
            if obj.type_name() == Some("ObjStm") {
                // Members were promoted to top-level objects; the container is
                // no longer needed.
                out.extend_from_slice(b"(deleted)");
            } else {
                self.write_object(&mut out, &obj)?;
            }
            if out
                .last()
                .map(|b| b.is_ascii_alphanumeric())
                .unwrap_or(false)
            {
                out.push(b'\n');
            }
            out.extend_from_slice(b"endobj\n");
        }

        // Classic xref table.
        let startxref = out.len();
        out.extend_from_slice(b"xref\n");
        out.extend_from_slice(format!("0 {}\n", maxobj + 1).as_bytes());
        for objid in 0..=maxobj {
            match offsets.get(&objid) {
                Some(&off) => {
                    out.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
                }
                None => {
                    out.extend_from_slice(b"0000000000 65535 f \n");
                }
            }
        }

        // Trailer.
        let mut trailer = self.doc.trailer.clone();
        trailer.remove("Prev");
        trailer.remove("XRefStm");
        trailer.remove("Encrypt");
        trailer.remove("DecodeParms");
        trailer.remove("Filter");
        trailer.remove("Index");
        trailer.remove("W");
        trailer.remove("Length");
        trailer.remove("Type");
        trailer.insert("Size".into(), Object::Int(maxobj as i64 + 1));
        out.extend_from_slice(b"trailer\n");
        self.write_object(&mut out, &Object::Dict(trailer))?;
        out.extend_from_slice(format!("\nstartxref\n{}\n%%EOF", startxref).as_bytes());
        Ok(out)
    }

    fn write_object(&self, out: &mut Vec<u8>, obj: &Object) -> Result<()> {
        match obj {
            Object::Null => out.extend_from_slice(b"null"),
            Object::Bool(b) => {
                sep_alnum(out);
                out.extend_from_slice(if *b { b"true" } else { b"false" });
            }
            Object::Int(n) => {
                sep_alnum(out);
                out.extend_from_slice(n.to_string().as_bytes());
            }
            Object::Real(r) => {
                sep_alnum(out);
                out.extend_from_slice(format_real(*r).as_bytes());
            }
            Object::Str(s) => {
                out.push(b'(');
                out.extend_from_slice(&escape_string(s));
                out.push(b')');
            }
            Object::Name(n) => {
                out.push(b'/');
                out.extend_from_slice(&escape_name(n));
            }
            Object::Array(a) => {
                out.push(b'[');
                for item in a {
                    self.write_object(out, item)?;
                }
                out.push(b']');
            }
            Object::Dict(d) => self.write_dict(out, d)?,
            Object::Ref(objid, _) => {
                sep_alnum(out);
                out.extend_from_slice(format!("{} 0 R", objid).as_bytes());
            }
            Object::Stream(s) => {
                self.write_dict(out, &s.dict)?;
                out.extend_from_slice(b"stream\n");
                out.extend_from_slice(&s.rawdata);
                out.extend_from_slice(b"\nendstream");
            }
            Object::Keyword(k) => {
                sep_alnum(out);
                out.extend_from_slice(k);
            }
        }
        Ok(())
    }

    fn write_dict(&self, out: &mut Vec<u8>, dict: &Dict) -> Result<()> {
        out.extend_from_slice(b"<<");
        for (key, val) in dict {
            out.push(b'/');
            out.extend_from_slice(&escape_name(key));
            self.write_object(out, val)?;
        }
        out.extend_from_slice(b">>");
        Ok(())
    }
}

/// Insert a space if the previous byte would otherwise merge with a token.
fn sep_alnum(out: &mut Vec<u8>) {
    if out
        .last()
        .map(|b| b.is_ascii_alphanumeric())
        .unwrap_or(false)
    {
        out.push(b' ');
    }
}

/// Escape a literal string body for `(…)` serialization.
fn escape_string(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for &b in s {
        match b {
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'(' => out.extend_from_slice(b"\\("),
            b')' => out.extend_from_slice(b"\\)"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            _ => out.push(b),
        }
    }
    out
}

/// Escape a name body: non-regular characters become `#xx`.
fn escape_name(n: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(n.len());
    for &b in n.as_bytes() {
        if b.is_ascii_alphanumeric() {
            out.push(b);
        } else {
            out.extend_from_slice(format!("#{:02x}", b).as_bytes());
        }
    }
    out
}

/// Format a real number without scientific notation, trimming trailing zeros.
fn format_real(r: f64) -> String {
    if r == r.trunc() && r.abs() < 1e15 {
        return format!("{}", r as i64);
    }
    let mut s = format!("{:.6}", r);
    while s.ends_with('0') {
        s.pop();
    }
    if s.ends_with('.') {
        s.pop();
    }
    s
}
