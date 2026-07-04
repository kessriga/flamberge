//! [`PdfDocument`]: the cross-reference chain, the merged trailer, and lazy
//! object resolution.
//!
//! Supports classic `xref` tables and PDF-1.5 cross-reference streams (following
//! `/Prev` and `/XRefStm`), plus object streams (`ObjStm`). Objects are parsed
//! on demand and cached; the actual token/object parsing lives in
//! [`super::parser`].

use super::lexer::{Lexer, Token};
use super::object::{Dict, Object};
use super::parser::{expect_int, object_from_token, parse_object};
use crate::{FormatError, Result};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};

/// The unboxed per-object decipher: `(objid, genno, bytes) -> plaintext`.
pub type DecipherFn = dyn Fn(u32, u16, &[u8]) -> Vec<u8>;

/// A per-object decipher hook.
///
/// Installed by the scheme layer via [`PdfDocument::set_decipher`] once the book
/// key is recovered; it carries all the crypto (RC4/AES + the MD5 per-object key
/// derivation). Symmetric ciphers make this the same closure for encrypt/decrypt.
pub type Decipher = Box<DecipherFn>;

/// One cross-reference entry: where object `objid` lives.
#[derive(Clone, Debug)]
enum XRefEntry {
    /// Uncompressed object at byte `offset` in the file.
    Uncompressed { offset: usize },
    /// Compressed object: member `index` of object-stream `stmid`.
    InObjStm { stmid: u32, index: usize },
}

/// A single cross-reference section (classic table or xref stream) plus its
/// trailer dictionary.
#[derive(Clone, Debug, Default)]
struct XRef {
    offsets: HashMap<u32, XRefEntry>,
    trailer: Dict,
}

/// A parsed PDF document: the cross-reference chain, the merged trailer, and a
/// lazy object cache. Objects are parsed on demand via [`Self::get_object`].
pub struct PdfDocument {
    data: Vec<u8>,
    /// The `%PDF-x.y` header line (first 8 bytes), re-emitted verbatim.
    pub(super) version: Vec<u8>,
    xrefs: Vec<XRef>,
    pub(super) trailer: Dict,
    cache: RefCell<HashMap<u32, Object>>,
    /// Parsed object streams, keyed by container id: `(N, flat member list)`.
    objstm_cache: RefCell<HashMap<u32, (usize, Vec<Object>)>>,
    /// Object ids currently being resolved — a re-entrancy guard against
    /// self- or mutually-referencing cross-reference entries in crafted files.
    resolving: RefCell<HashSet<u32>>,
    /// Optional per-object decipher, installed via [`Self::set_decipher`].
    decipher: RefCell<Option<Decipher>>,
    /// The `/Encrypt` object id, skipped by the decipher (its strings are never
    /// enciphered). `None` when `/Encrypt` is a direct dict or absent.
    encrypt_skip: Cell<Option<u32>>,
}

impl std::fmt::Debug for PdfDocument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PdfDocument")
            .field("bytes", &self.data.len())
            .field("xref_sections", &self.xrefs.len())
            .field("objects", &self.object_ids().len())
            .finish()
    }
}

impl PdfDocument {
    /// Parse a PDF from its raw bytes: read the cross-reference chain and
    /// trailer. Objects themselves are parsed lazily.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let version = data.get(0..8).unwrap_or(data).to_vec();
        let mut doc = PdfDocument {
            data: data.to_vec(),
            version,
            xrefs: Vec::new(),
            trailer: Dict::new(),
            cache: RefCell::new(HashMap::new()),
            objstm_cache: RefCell::new(HashMap::new()),
            resolving: RefCell::new(HashSet::new()),
            decipher: RefCell::new(None),
            encrypt_skip: Cell::new(None),
        };
        doc.read_xrefs()?;
        Ok(doc)
    }

    /// Install a per-object [`Decipher`]: from now on, [`Self::get_object`]
    /// deciphers each uncompressed object's string and stream bytes as it is
    /// read (mirroring `ineptpdf`'s `getobj` + `decipher_all`).
    ///
    /// Clears the object caches so anything read before the decipher was
    /// installed (e.g. while probing `/Encrypt`) is re-fetched as plaintext, and
    /// records the `/Encrypt` object id so its own (unenciphered) strings are
    /// left untouched.
    pub fn set_decipher(&self, decipher: Decipher) {
        self.cache.borrow_mut().clear();
        self.objstm_cache.borrow_mut().clear();
        self.encrypt_skip.set(match self.trailer.get("Encrypt") {
            Some(Object::Ref(objid, _)) => Some(*objid),
            _ => None,
        });
        *self.decipher.borrow_mut() = Some(decipher);
    }

    /// The union of all object ids reachable through the cross-reference chain.
    pub fn object_ids(&self) -> Vec<u32> {
        let mut ids: Vec<u32> = Vec::new();
        let mut seen = HashSet::new();
        for xref in &self.xrefs {
            for &id in xref.offsets.keys() {
                if seen.insert(id) {
                    ids.push(id);
                }
            }
        }
        ids.sort_unstable();
        ids
    }

    /// The document trailer (merged: `/Root`, `/Info`, `/ID`, `/Encrypt`, …).
    pub fn trailer(&self) -> &Dict {
        &self.trailer
    }

    /// The `/Encrypt` dictionary value, if the document is encrypted.
    pub fn encrypt(&self) -> Option<&Object> {
        self.trailer.get("Encrypt")
    }

    /// The `/ID` array, if present.
    pub fn id(&self) -> Option<&Object> {
        self.trailer.get("ID")
    }

    /// Follow indirect references until a direct object is reached.
    pub fn resolve(&self, obj: &Object) -> Result<Object> {
        let mut cur = obj.clone();
        let mut guard = 0;
        while let Object::Ref(objid, _) = cur {
            cur = self.get_object(objid)?;
            guard += 1;
            if guard > 100 {
                return Err(FormatError::Invalid("pdf: reference cycle".into()));
            }
        }
        Ok(cur)
    }

    /// Fetch (and cache) an object by id, resolving compressed objects from
    /// their object stream.
    pub fn get_object(&self, objid: u32) -> Result<Object> {
        if let Some(obj) = self.cache.borrow().get(&objid) {
            return Ok(obj.clone());
        }
        // Guard against a cross-reference entry that resolves (directly or via
        // an object-stream container) back to the object being resolved.
        if !self.resolving.borrow_mut().insert(objid) {
            return Err(FormatError::Invalid(format!(
                "pdf: reference cycle resolving object {}",
                objid
            )));
        }
        let built = self.build_object(objid);
        self.resolving.borrow_mut().remove(&objid);
        let obj = built?;
        self.cache.borrow_mut().insert(objid, obj.clone());
        Ok(obj)
    }

    /// Parse `objid` from its cross-reference entry (no caching / cycle guard;
    /// callers go through [`Self::get_object`]).
    fn build_object(&self, objid: u32) -> Result<Object> {
        let entry = self
            .locate(objid)
            .ok_or_else(|| FormatError::Invalid(format!("pdf: object {} not found", objid)))?;
        match entry {
            XRefEntry::Uncompressed { offset } => self.parse_indirect_at(offset, objid),
            XRefEntry::InObjStm { stmid, index } => self.parse_from_objstm(stmid, index),
        }
    }

    /// Find the cross-reference entry for `objid`, newest section first.
    fn locate(&self, objid: u32) -> Option<XRefEntry> {
        for xref in &self.xrefs {
            if let Some(e) = xref.offsets.get(&objid) {
                return Some(e.clone());
            }
        }
        None
    }

    /// Parse an uncompressed indirect object `objid genno obj … endobj`.
    fn parse_indirect_at(&self, offset: usize, objid: u32) -> Result<Object> {
        if offset >= self.data.len() {
            return Err(FormatError::Invalid(format!(
                "pdf: object {} offset {} out of range",
                objid, offset
            )));
        }
        let mut lex = Lexer::at(&self.data, offset);
        let _objid = expect_int(&mut lex)?;
        let genno = expect_int(&mut lex)?;
        match lex.next_token()? {
            Some(Token::Keyword(ref k)) if k == b"obj" => {}
            other => {
                return Err(FormatError::Invalid(format!(
                    "pdf: expected 'obj' for object {}, got {:?}",
                    objid, other
                )));
            }
        }
        let genno = genno.max(0) as u16;
        let mut obj = parse_object(&mut lex, Some(self))?;
        if let Object::Stream(ref mut s) = obj {
            s.objid = objid;
            s.genno = genno;
        }
        // Decipher in place (uncompressed objects only; object-stream members are
        // already covered by their deciphered container). The `/Encrypt` dict is
        // never enciphered, so it is skipped.
        if self.encrypt_skip.get() != Some(objid) {
            if let Some(decipher) = self.decipher.borrow().as_ref() {
                obj = decipher_all(decipher.as_ref(), objid, genno, obj);
            }
        }
        Ok(obj)
    }

    /// Extract member `index` from object stream `stmid`.
    fn parse_from_objstm(&self, stmid: u32, index: usize) -> Result<Object> {
        if !self.objstm_cache.borrow().contains_key(&stmid) {
            let container = self.get_object(stmid)?;
            let stream = match &container {
                Object::Stream(s) => s,
                _ => {
                    return Err(FormatError::Invalid(format!(
                        "pdf: object stream {} is not a stream",
                        stmid
                    )));
                }
            };
            // Capture /N now, from the container we already hold, so member
            // lookups need not re-fetch (and re-clone) the whole container.
            let n = stream
                .dict
                .get("N")
                .and_then(Object::as_int)
                .unwrap_or(0)
                .max(0) as usize;
            let data = stream.decoded()?;
            // The decoded stream is a flat token sequence: 2*N header integers
            // (objnum, offset pairs) followed by the N member objects.
            let mut lex = Lexer::new(&data);
            let mut objs = Vec::new();
            while let Some(tok) = lex.next_token()? {
                objs.push(object_from_token(tok, &mut lex, None)?);
            }
            self.objstm_cache.borrow_mut().insert(stmid, (n, objs));
        }
        // The first 2*N entries are the header pairs, so member `index` sits at
        // flat position 2*N + index.
        let borrow = self.objstm_cache.borrow();
        let (n, objs) = borrow.get(&stmid).ok_or_else(|| {
            FormatError::Invalid(format!("pdf: object stream {} vanished", stmid))
        })?;
        let i = n * 2 + index;
        objs.get(i).cloned().ok_or_else(|| {
            FormatError::Invalid(format!(
                "pdf: object-stream {} has no member at index {}",
                stmid, index
            ))
        })
    }

    //
    // ── xref reading ────────────────────────────────────────────────────────
    //

    fn read_xrefs(&mut self) -> Result<()> {
        let start = self
            .find_startxref()
            .ok_or_else(|| FormatError::Invalid("pdf: 'startxref' not found".into()))?;
        let mut visited = HashSet::new();
        self.read_xref_from(start, &mut visited)?;
        // Pick the trailer: newest section that carries a /Root.
        for xref in &self.xrefs {
            if xref.trailer.contains_key("Root") {
                self.trailer = xref.trailer.clone();
                break;
            }
        }
        if self.trailer.is_empty() {
            if let Some(first) = self.xrefs.first() {
                self.trailer = first.trailer.clone();
            }
        }
        if !self.trailer.contains_key("Root") {
            return Err(FormatError::Invalid("pdf: no /Root in trailer".into()));
        }
        Ok(())
    }

    /// Locate the byte offset named by the final `startxref`.
    fn find_startxref(&self) -> Option<usize> {
        let needle = b"startxref";
        let hay = &self.data;
        let idx = hay.windows(needle.len()).rposition(|w| w == needle)?;
        let mut lex = Lexer::at(hay, idx + needle.len());
        match lex.next_token().ok()?? {
            Token::Int(n) if n >= 0 => Some(n as usize),
            _ => None,
        }
    }

    fn read_xref_from(&mut self, start: usize, visited: &mut HashSet<usize>) -> Result<()> {
        if !visited.insert(start) || start >= self.data.len() {
            return Ok(());
        }
        let mut lex = Lexer::at(&self.data, start);
        let save = lex.pos;
        let first = lex.next_token()?;
        let xref = match first {
            Some(Token::Keyword(ref k)) if k == b"xref" => self.read_classic_xref(&mut lex)?,
            Some(Token::Int(_)) => {
                // PDF-1.5 cross-reference stream: `objid genno obj << … >> stream`.
                lex.pos = save;
                self.read_xref_stream(&mut lex)?
            }
            other => {
                return Err(FormatError::Invalid(format!(
                    "pdf: expected xref at offset {}, got {:?}",
                    start, other
                )));
            }
        };
        let trailer = xref.trailer.clone();
        self.xrefs.push(xref);
        // Hybrid-reference files: follow the supplementary xref stream first.
        if let Some(Object::Int(pos)) = trailer.get("XRefStm") {
            if *pos >= 0 {
                self.read_xref_from(*pos as usize, visited)?;
            }
        }
        if let Some(Object::Int(pos)) = trailer.get("Prev") {
            if *pos >= 0 {
                self.read_xref_from(*pos as usize, visited)?;
            }
        }
        Ok(())
    }

    /// Parse a classic `xref` table plus its `trailer` dictionary.
    fn read_classic_xref(&self, lex: &mut Lexer) -> Result<XRef> {
        let mut xref = XRef::default();
        loop {
            match lex.next_token()? {
                Some(Token::Keyword(ref k)) if k == b"trailer" => break,
                Some(Token::Int(start)) => {
                    let count = expect_int(lex)?;
                    if start < 0 || count < 0 {
                        return Err(FormatError::Invalid("pdf: negative xref subsection".into()));
                    }
                    for i in 0..count as u32 {
                        let offset = expect_int(lex)?;
                        let _gen = expect_int(lex)?;
                        let kind = match lex.next_token()? {
                            Some(Token::Keyword(k)) => k,
                            other => {
                                return Err(FormatError::Invalid(format!(
                                    "pdf: bad xref entry type {:?}",
                                    other
                                )));
                            }
                        };
                        if kind == b"n" && offset >= 0 {
                            xref.offsets.insert(
                                start as u32 + i,
                                XRefEntry::Uncompressed {
                                    offset: offset as usize,
                                },
                            );
                        }
                    }
                }
                other => {
                    return Err(FormatError::Invalid(format!(
                        "pdf: unexpected token in xref table: {:?}",
                        other
                    )));
                }
            }
        }
        let dict = parse_object(lex, Some(self))?;
        xref.trailer = match dict {
            Object::Dict(d) => d,
            _ => return Err(FormatError::Invalid("pdf: trailer is not a dict".into())),
        };
        Ok(xref)
    }

    /// Parse a PDF-1.5 cross-reference stream at the lexer's position.
    fn read_xref_stream(&self, lex: &mut Lexer) -> Result<XRef> {
        let _objid = expect_int(lex)?;
        let _genno = expect_int(lex)?;
        match lex.next_token()? {
            Some(Token::Keyword(ref k)) if k == b"obj" => {}
            other => {
                return Err(FormatError::Invalid(format!(
                    "pdf: expected 'obj' for xref stream, got {:?}",
                    other
                )));
            }
        }
        let obj = parse_object(lex, Some(self))?;
        let stream = match obj {
            Object::Stream(s) => s,
            _ => {
                return Err(FormatError::Invalid(
                    "pdf: xref object is not a stream".into(),
                ))
            }
        };
        let dict = &stream.dict;
        let size = dict
            .get("Size")
            .and_then(Object::as_int)
            .ok_or_else(|| FormatError::Invalid("pdf: xref stream missing /Size".into()))?;
        let widths: Vec<i64> = dict
            .get("W")
            .and_then(Object::as_array)
            .map(|a| a.iter().filter_map(Object::as_int).collect())
            .unwrap_or_default();
        if widths.len() != 3 {
            return Err(FormatError::Invalid(
                "pdf: xref stream /W must have 3 ints".into(),
            ));
        }
        let (w1, w2, w3) = (widths[0] as usize, widths[1] as usize, widths[2] as usize);
        let entlen = w1 + w2 + w3;
        if entlen == 0 {
            return Err(FormatError::Invalid("pdf: xref stream /W all zero".into()));
        }

        // /Index defaults to [0 Size]; it is a flat list of (first, count) pairs.
        let index: Vec<i64> = match dict.get("Index").and_then(Object::as_array) {
            Some(a) => a.iter().filter_map(Object::as_int).collect(),
            None => vec![0, size],
        };

        let data = stream.decoded()?;
        let mut xref = XRef::default();
        let mut pos = 0usize;
        let mut pair = index.chunks(2);
        while let Some(&[first, count]) = pair.next() {
            for k in 0..count.max(0) {
                if pos + entlen > data.len() {
                    break;
                }
                let ent = &data[pos..pos + entlen];
                pos += entlen;
                // A zero-width type field defaults to type 1 (PDF spec §7.5.8.2).
                let f1 = if w1 == 0 { 1 } else { nunpack(&ent[0..w1]) };
                let f2 = nunpack(&ent[w1..w1 + w2]);
                let f3 = nunpack(&ent[w1 + w2..]);
                let objid = (first + k) as u32;
                match f1 {
                    1 => {
                        xref.offsets.insert(
                            objid,
                            XRefEntry::Uncompressed {
                                offset: f2 as usize,
                            },
                        );
                    }
                    2 => {
                        xref.offsets.insert(
                            objid,
                            XRefEntry::InObjStm {
                                stmid: f2 as u32,
                                index: f3 as usize,
                            },
                        );
                    }
                    _ => { /* type 0 = free object */ }
                }
            }
        }
        // The xref stream's own dictionary is the trailer.
        xref.trailer = stream.dict;
        Ok(xref)
    }
}

/// Recursively decipher an object's string/stream bytes with `f`.
///
/// Strings are deciphered directly; arrays and dictionaries are walked; a
/// stream's *body* is deciphered but its dictionary is left as-is — matching
/// `ineptpdf.decipher_all`, which returns a `PDFStream` unchanged and deciphers
/// only its raw data lazily. `objid`/`genno` are the enclosing object's, as the
/// PDF security handler keys every nested string to its top-level object.
fn decipher_all(f: &DecipherFn, objid: u32, genno: u16, obj: Object) -> Object {
    match obj {
        Object::Str(bytes) => Object::Str(f(objid, genno, &bytes)),
        Object::Array(items) => Object::Array(
            items
                .into_iter()
                .map(|v| decipher_all(f, objid, genno, v))
                .collect(),
        ),
        Object::Dict(dict) => Object::Dict(
            dict.into_iter()
                .map(|(k, v)| (k, decipher_all(f, objid, genno, v)))
                .collect(),
        ),
        Object::Stream(mut s) => {
            s.rawdata = f(objid, genno, &s.rawdata);
            Object::Stream(s)
        }
        other => other,
    }
}

/// Unpack up to 8 big-endian bytes into a `u64`.
fn nunpack(bytes: &[u8]) -> u64 {
    let mut v = 0u64;
    for &b in bytes {
        v = v << 8 | b as u64;
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdf::PdfSerializer;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// Build a minimal but valid classic-xref PDF for round-trip tests.
    fn build_classic_pdf() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"%PDF-1.4\n");
        let mut offsets = Vec::new();

        offsets.push((1u32, buf.len()));
        buf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

        offsets.push((2u32, buf.len()));
        buf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

        offsets.push((3u32, buf.len()));
        buf.extend_from_slice(
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n",
        );

        let xref_pos = buf.len();
        buf.extend_from_slice(b"xref\n0 4\n");
        buf.extend_from_slice(b"0000000000 65535 f \n");
        for (_, off) in &offsets {
            buf.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
        }
        buf.extend_from_slice(b"trailer\n<< /Size 4 /Root 1 0 R >>\n");
        buf.extend_from_slice(format!("startxref\n{}\n%%EOF", xref_pos).as_bytes());
        buf
    }

    #[test]
    fn parse_classic_pdf() {
        let pdf = build_classic_pdf();
        let doc = PdfDocument::parse(&pdf).unwrap();
        assert_eq!(doc.object_ids(), vec![1, 2, 3]);
        let root = doc.trailer().get("Root").cloned().unwrap();
        let catalog = doc.resolve(&root).unwrap();
        assert_eq!(catalog.type_name(), Some("Catalog"));
        let pages = doc
            .resolve(catalog.as_dict().unwrap().get("Pages").unwrap())
            .unwrap();
        assert_eq!(pages.as_dict().unwrap().get("Count"), Some(&Object::Int(1)));
        assert!(doc.encrypt().is_none());
    }

    #[test]
    fn serialize_roundtrip_preserves_content() {
        let pdf = build_classic_pdf();
        let doc = PdfDocument::parse(&pdf).unwrap();
        let out = PdfSerializer::new(&doc).serialize().unwrap();

        // Re-parse the serialized output and compare object graphs.
        let doc2 = PdfDocument::parse(&out).unwrap();
        assert_eq!(doc.object_ids(), doc2.object_ids());
        for id in doc.object_ids() {
            assert_eq!(
                doc.get_object(id).unwrap(),
                doc2.get_object(id).unwrap(),
                "object {} differs after round trip",
                id
            );
        }
        // The Page's MediaBox survives.
        let page = doc2.get_object(3).unwrap();
        assert_eq!(
            page.as_dict().unwrap().get("MediaBox"),
            Some(&Object::Array(vec![
                Object::Int(0),
                Object::Int(0),
                Object::Int(612),
                Object::Int(792),
            ]))
        );
    }

    /// Build a PDF whose cross-reference section is a PDF-1.5 xref stream, and
    /// which stores object 1 (the catalog) inside an object stream.
    fn build_xref_stream_pdf() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"%PDF-1.5\n");

        // Object 2: an ObjStm containing object 1 (the catalog).
        // Members: obj 1 = "<< /Type /Catalog /Pages 3 0 R >>".
        let member = b"<< /Type /Catalog /Pages 3 0 R >>";
        let header = b"1 0 "; // objnum=1, offset=0
        let (objstm_plain, first) = {
            let mut d = Vec::new();
            d.extend_from_slice(header);
            let first = d.len();
            d.extend_from_slice(member);
            (d, first)
        };
        let objstm_comp = zlib(&objstm_plain);
        let obj2_off = buf.len();
        buf.extend_from_slice(
            format!(
                "2 0 obj\n<< /Type /ObjStm /N 1 /First {} /Length {} /Filter /FlateDecode >>\nstream\n",
                first,
                objstm_comp.len()
            )
            .as_bytes(),
        );
        buf.extend_from_slice(&objstm_comp);
        buf.extend_from_slice(b"\nendstream\nendobj\n");

        // Object 3: the Pages object (uncompressed).
        let obj3_off = buf.len();
        buf.extend_from_slice(b"3 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n");

        // Object 4: the xref stream itself. Index covers objects 0..=4.
        // W = [1,2,2]. Entries:
        //   0: type 0 (free)
        //   1: type 2, in objstm 2, index 0
        //   2: type 1, offset obj2_off
        //   3: type 1, offset obj3_off
        //   4: type 1, offset (this object's own offset)
        let obj4_off = buf.len();
        let mut xref_data = Vec::new();
        let push_entry = |v: &mut Vec<u8>, f1: u8, f2: u16, f3: u16| {
            v.push(f1);
            v.extend_from_slice(&f2.to_be_bytes());
            v.extend_from_slice(&f3.to_be_bytes());
        };
        push_entry(&mut xref_data, 0, 0, 0);
        push_entry(&mut xref_data, 2, 2, 0);
        push_entry(&mut xref_data, 1, obj2_off as u16, 0);
        push_entry(&mut xref_data, 1, obj3_off as u16, 0);
        push_entry(&mut xref_data, 1, obj4_off as u16, 0);
        let xref_comp = zlib(&xref_data);
        buf.extend_from_slice(
            format!(
                "4 0 obj\n<< /Type /XRef /Size 5 /Root 1 0 R /W [1 2 2] /Filter /FlateDecode /Length {} >>\nstream\n",
                xref_comp.len()
            )
            .as_bytes(),
        );
        buf.extend_from_slice(&xref_comp);
        buf.extend_from_slice(b"\nendstream\nendobj\n");

        buf.extend_from_slice(format!("startxref\n{}\n%%EOF", obj4_off).as_bytes());
        buf
    }

    #[test]
    fn parse_xref_stream_and_objstm() {
        let pdf = build_xref_stream_pdf();
        let doc = PdfDocument::parse(&pdf).unwrap();
        // Object 1 lives inside the object stream.
        let catalog = doc.get_object(1).unwrap();
        assert_eq!(catalog.type_name(), Some("Catalog"));
        // Its /Pages reference resolves to the uncompressed object 3.
        let pages = doc
            .resolve(catalog.as_dict().unwrap().get("Pages").unwrap())
            .unwrap();
        assert_eq!(pages.type_name(), Some("Pages"));
        // Trailer /Root comes from the xref stream dict.
        assert_eq!(doc.trailer().get("Root"), Some(&Object::Ref(1, 0)));
    }

    #[test]
    fn xref_stream_serializes_to_classic() {
        let pdf = build_xref_stream_pdf();
        let doc = PdfDocument::parse(&pdf).unwrap();
        let out = PdfSerializer::new(&doc).serialize().unwrap();
        // Re-parse: the output must be a classic-xref PDF that still exposes the
        // catalog and pages.
        let doc2 = PdfDocument::parse(&out).unwrap();
        let catalog = doc2.get_object(1).unwrap();
        assert_eq!(catalog.type_name(), Some("Catalog"));
        let pages = doc2
            .resolve(catalog.as_dict().unwrap().get("Pages").unwrap())
            .unwrap();
        assert_eq!(pages.type_name(), Some("Pages"));
    }

    /// A crafted xref stream whose object 1 is marked as living inside object
    /// stream 1 (itself). Resolving it must error, not recurse to a stack
    /// overflow.
    fn build_self_referential_objstm_pdf() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"%PDF-1.5\n");

        // Object 2: the xref stream. W = [1,2,2]; entries for objects 0..=2:
        //   0: free
        //   1: type 2 → InObjStm{ stmid: 1, index: 0 }  (self-referential)
        //   2: type 1 → this xref stream's own offset
        let obj2_off = buf.len();
        let mut xref_data = Vec::new();
        let push_entry = |v: &mut Vec<u8>, f1: u8, f2: u16, f3: u16| {
            v.push(f1);
            v.extend_from_slice(&f2.to_be_bytes());
            v.extend_from_slice(&f3.to_be_bytes());
        };
        push_entry(&mut xref_data, 0, 0, 0);
        push_entry(&mut xref_data, 2, 1, 0);
        push_entry(&mut xref_data, 1, obj2_off as u16, 0);
        let xref_comp = zlib(&xref_data);
        buf.extend_from_slice(
            format!(
                "2 0 obj\n<< /Type /XRef /Size 3 /Root 1 0 R /W [1 2 2] /Filter /FlateDecode /Length {} >>\nstream\n",
                xref_comp.len()
            )
            .as_bytes(),
        );
        buf.extend_from_slice(&xref_comp);
        buf.extend_from_slice(b"\nendstream\nendobj\n");
        buf.extend_from_slice(format!("startxref\n{}\n%%EOF", obj2_off).as_bytes());
        buf
    }

    #[test]
    fn self_referential_objstm_errors_without_overflow() {
        let pdf = build_self_referential_objstm_pdf();
        let doc = PdfDocument::parse(&pdf).unwrap();
        let err = doc.get_object(1).unwrap_err();
        assert!(
            matches!(&err, FormatError::Invalid(m) if m.contains("cycle")),
            "expected a cycle error, got {:?}",
            err
        );
    }
}
