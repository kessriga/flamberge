//! PDF tokenizer / object model for ADEPT (`EBX_HANDLER`) and B&N PDFs.
//!
//! A faithful, in-memory port of the pdfminer-derived parser in `ineptpdf.py`:
//! a lexer + recursive-descent object parser, the indirect-object graph, classic
//! `xref` tables **and** PDF-1.5 cross-reference streams, object streams
//! (`ObjStm`), and the stream filters `FlateDecode` / `LZWDecode` /
//! `ASCII85Decode` with the PNG predictor. A [`PdfSerializer`] re-emits a clean
//! PDF (classic xref, generation numbers forced to 0, `/Encrypt` dropped).
//!
//! Decryption is intentionally **out of scope** here (see TASK-12): the
//! `/Encrypt` dict and `/ID` are exposed for the scheme layer, which deciphers
//! each object's stream/string bytes with an MD5-derived per-object key.
//!
//! Where `ineptpdf.py` streams bytes through a buffer-refilling `PSBaseParser`
//! (a workaround for Python file I/O), this port keeps the whole document in a
//! `Vec<u8>` and drives a simple cursor — the token grammar is identical.
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §7.4. Original: `ineptpdf.py`.

use crate::{FormatError, Result};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::io::Read;

/// The three ADEPT/B&N `/Encrypt` `/Filter` values.
pub const FILTER_STANDARD: &str = "Standard";
pub const FILTER_ADOBE_APS: &str = "Adobe.APS";
pub const FILTER_EBX_HANDLER: &str = "EBX_HANDLER";

/// A PDF dictionary: name → object. Keys are stored without the leading `/`.
///
/// A `BTreeMap` gives deterministic serialization order; PDF dictionaries are
/// unordered, so this loses no information.
pub type Dict = BTreeMap<String, Object>;

/// A parsed PDF object.
///
/// `Ref(objid, genno)` is an *unresolved* indirect reference; call
/// [`PdfDocument::resolve`] (or [`PdfDocument::get_object`]) to follow it.
/// `Keyword` only appears for stray bare tokens and is not produced for valid
/// object graphs; it exists so the parser never silently drops input.
#[derive(Clone, Debug, PartialEq)]
pub enum Object {
    Null,
    Bool(bool),
    Int(i64),
    Real(f64),
    /// Literal `(…)` or hex `<…>` string, decoded to raw bytes.
    Str(Vec<u8>),
    /// A `/Name`, stored without the leading slash and with `#xx` escapes decoded.
    Name(String),
    Array(Vec<Object>),
    Dict(Dict),
    Stream(PdfStream),
    /// Indirect reference `objid genno R`.
    Ref(u32, u16),
    /// A bare keyword token (rare; e.g. an operator outside a content stream).
    Keyword(Vec<u8>),
}

/// A PDF stream object: its dictionary plus the raw (still-encoded) body bytes.
///
/// Decoding (filters, predictor) is done on demand by [`PdfStream::decoded`];
/// the raw bytes are what a decryptor operates on before filters are applied.
#[derive(Clone, Debug, PartialEq)]
pub struct PdfStream {
    pub dict: Dict,
    pub rawdata: Vec<u8>,
    pub objid: u32,
    pub genno: u16,
}

impl Object {
    /// Borrow as an integer if this object is an `Int`.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Object::Int(n) => Some(*n),
            _ => None,
        }
    }

    /// Borrow as a name if this object is a `Name`.
    pub fn as_name(&self) -> Option<&str> {
        match self {
            Object::Name(s) => Some(s),
            _ => None,
        }
    }

    /// Borrow as a dictionary (also unwraps a stream's dictionary).
    pub fn as_dict(&self) -> Option<&Dict> {
        match self {
            Object::Dict(d) => Some(d),
            Object::Stream(s) => Some(&s.dict),
            _ => None,
        }
    }

    /// Borrow as an array.
    pub fn as_array(&self) -> Option<&[Object]> {
        match self {
            Object::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Borrow as a stream.
    pub fn as_stream(&self) -> Option<&PdfStream> {
        match self {
            Object::Stream(s) => Some(s),
            _ => None,
        }
    }

    /// Borrow as raw string bytes.
    pub fn as_str_bytes(&self) -> Option<&[u8]> {
        match self {
            Object::Str(b) => Some(b),
            _ => None,
        }
    }
}

//
// ─── Lexer ──────────────────────────────────────────────────────────────────
//

/// A single lexical token. Delimiters `<<`, `>>`, `[`, `]` are distinct
/// variants; all other bare word tokens (`obj`, `R`, `stream`, `n`, `f`, …)
/// become `Keyword`. `true`/`false`/`null` are folded into value tokens.
#[derive(Clone, Debug, PartialEq)]
enum Token {
    Int(i64),
    Real(f64),
    Bool(bool),
    Null,
    Str(Vec<u8>),
    Name(String),
    ArrayOpen,
    ArrayClose,
    DictOpen,
    DictClose,
    Keyword(Vec<u8>),
}

/// True for PDF whitespace bytes (§7.2.2 of the PDF spec).
fn is_ws(b: u8) -> bool {
    matches!(b, b'\0' | b'\t' | b'\n' | b'\x0c' | b'\r' | b' ')
}

/// True for PDF delimiter bytes.
fn is_delim(b: u8) -> bool {
    matches!(
        b,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

/// True for "regular" characters (name/keyword/number body).
fn is_regular(b: u8) -> bool {
    !is_ws(b) && !is_delim(b)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Cursor-based tokenizer over the whole PDF byte buffer.
struct Lexer<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn new(data: &'a [u8]) -> Self {
        Lexer { data, pos: 0 }
    }

    fn at(data: &'a [u8], pos: usize) -> Self {
        Lexer { data, pos }
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    /// Skip whitespace and `%`-comments (to end of line).
    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if is_ws(b) {
                self.pos += 1;
            } else if b == b'%' {
                while let Some(c) = self.peek() {
                    self.pos += 1;
                    if c == b'\n' || c == b'\r' {
                        break;
                    }
                }
            } else {
                break;
            }
        }
    }

    /// Read the next token, or `None` at end of input.
    fn next_token(&mut self) -> Result<Option<Token>> {
        self.skip_ws();
        let b = match self.peek() {
            Some(b) => b,
            None => return Ok(None),
        };
        match b {
            b'/' => Ok(Some(self.read_name()?)),
            b'(' => Ok(Some(self.read_literal_string()?)),
            b'<' => {
                if self.data.get(self.pos + 1) == Some(&b'<') {
                    self.pos += 2;
                    Ok(Some(Token::DictOpen))
                } else {
                    Ok(Some(self.read_hex_string()?))
                }
            }
            b'>' => {
                if self.data.get(self.pos + 1) == Some(&b'>') {
                    self.pos += 2;
                    Ok(Some(Token::DictClose))
                } else {
                    Err(FormatError::Invalid(format!(
                        "pdf: stray '>' at offset {}",
                        self.pos
                    )))
                }
            }
            b'[' => {
                self.pos += 1;
                Ok(Some(Token::ArrayOpen))
            }
            b']' => {
                self.pos += 1;
                Ok(Some(Token::ArrayClose))
            }
            b'{' | b'}' => {
                // PostScript procedure delimiters — not used by PDF object
                // syntax, but tokenize them so we never loop forever.
                self.pos += 1;
                Ok(Some(Token::Keyword(vec![b])))
            }
            b'+' | b'-' | b'.' | b'0'..=b'9' => Ok(Some(self.read_number())),
            _ => Ok(Some(self.read_keyword())),
        }
    }

    fn read_name(&mut self) -> Result<Token> {
        self.pos += 1; // consume '/'
        let mut out = Vec::new();
        while let Some(b) = self.peek() {
            if !is_regular(b) {
                break;
            }
            self.pos += 1;
            if b == b'#' {
                let h = self.peek().and_then(hex_val);
                let l = self.data.get(self.pos + 1).copied().and_then(hex_val);
                if let (Some(h), Some(l)) = (h, l) {
                    out.push(h << 4 | l);
                    self.pos += 2;
                    continue;
                }
                // Malformed escape: keep the literal '#'.
                out.push(b'#');
            } else {
                out.push(b);
            }
        }
        Ok(Token::Name(String::from_utf8_lossy(&out).into_owned()))
    }

    fn read_literal_string(&mut self) -> Result<Token> {
        self.pos += 1; // consume '('
        let mut out = Vec::new();
        let mut depth = 1usize;
        while let Some(b) = self.peek() {
            self.pos += 1;
            match b {
                b'(' => {
                    depth += 1;
                    out.push(b);
                }
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(Token::Str(out));
                    }
                    out.push(b);
                }
                b'\\' => {
                    let e = match self.peek() {
                        Some(e) => e,
                        None => break,
                    };
                    self.pos += 1;
                    match e {
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'(' => out.push(b'('),
                        b')' => out.push(b')'),
                        b'\\' => out.push(b'\\'),
                        b'\r' => {
                            // line continuation: swallow an optional \n too
                            if self.peek() == Some(b'\n') {
                                self.pos += 1;
                            }
                        }
                        b'\n' => { /* line continuation */ }
                        b'0'..=b'7' => {
                            let mut val = (e - b'0') as u32;
                            for _ in 0..2 {
                                match self.peek() {
                                    Some(d @ b'0'..=b'7') => {
                                        val = val * 8 + (d - b'0') as u32;
                                        self.pos += 1;
                                    }
                                    _ => break,
                                }
                            }
                            out.push(val as u8);
                        }
                        other => out.push(other),
                    }
                }
                _ => out.push(b),
            }
        }
        Err(FormatError::Invalid(
            "pdf: unterminated literal string".into(),
        ))
    }

    fn read_hex_string(&mut self) -> Result<Token> {
        self.pos += 1; // consume '<'
        let mut nibbles = Vec::new();
        loop {
            let b = match self.peek() {
                Some(b) => b,
                None => {
                    return Err(FormatError::Invalid("pdf: unterminated hex string".into()));
                }
            };
            self.pos += 1;
            if b == b'>' {
                break;
            }
            if is_ws(b) {
                continue;
            }
            match hex_val(b) {
                Some(v) => nibbles.push(v),
                None => {
                    return Err(FormatError::Invalid(format!(
                        "pdf: bad hex digit {:#x} in hex string",
                        b
                    )));
                }
            }
        }
        // An odd final nibble is padded with 0 (PDF spec §7.3.4.3).
        let mut out = Vec::with_capacity(nibbles.len().div_ceil(2));
        let mut i = 0;
        while i < nibbles.len() {
            let hi = nibbles[i];
            let lo = if i + 1 < nibbles.len() {
                nibbles[i + 1]
            } else {
                0
            };
            out.push(hi << 4 | lo);
            i += 2;
        }
        Ok(Token::Str(out))
    }

    fn read_number(&mut self) -> Token {
        let start = self.pos;
        let mut is_real = false;
        if matches!(self.peek(), Some(b'+') | Some(b'-')) {
            self.pos += 1;
        }
        while let Some(b) = self.peek() {
            match b {
                b'0'..=b'9' => self.pos += 1,
                b'.' => {
                    is_real = true;
                    self.pos += 1;
                }
                _ => break,
            }
        }
        let text = String::from_utf8_lossy(&self.data[start..self.pos]);
        if is_real {
            match text.parse::<f64>() {
                Ok(v) => Token::Real(v),
                // e.g. a lone "." or "-." — treat as 0.0 like pdfminer's lax mode
                Err(_) => Token::Real(0.0),
            }
        } else {
            match text.parse::<i64>() {
                Ok(v) => Token::Int(v),
                Err(_) => Token::Real(text.parse::<f64>().unwrap_or(0.0)),
            }
        }
    }

    fn read_keyword(&mut self) -> Token {
        let start = self.pos;
        while let Some(b) = self.peek() {
            if !is_regular(b) {
                break;
            }
            self.pos += 1;
        }
        let word = &self.data[start..self.pos];
        match word {
            b"true" => Token::Bool(true),
            b"false" => Token::Bool(false),
            b"null" => Token::Null,
            _ if start == self.pos => {
                // Not a regular char and not a handled delimiter; consume one
                // byte as a keyword so the lexer always makes progress.
                self.pos += 1;
                Token::Keyword(self.data[start..self.pos].to_vec())
            }
            _ => Token::Keyword(word.to_vec()),
        }
    }
}

//
// ─── Object parser ──────────────────────────────────────────────────────────
//

/// Parse exactly one object starting at `lex`'s current position.
///
/// Handles the `n g R` indirect-reference form via bounded look-ahead. Stream
/// bodies are read by `parse_stream_body`, which needs the document to resolve
/// an indirect `/Length`; when `doc` is `None` (e.g. parsing an object-stream's
/// flat token list, which never contains streams) the `stream` keyword is left
/// to fall through as a bare keyword.
fn parse_object(lex: &mut Lexer, doc: Option<&PdfDocument>) -> Result<Object> {
    let tok = lex
        .next_token()?
        .ok_or_else(|| FormatError::Invalid("pdf: unexpected EOF parsing object".into()))?;
    object_from_token(tok, lex, doc)
}

fn object_from_token(tok: Token, lex: &mut Lexer, doc: Option<&PdfDocument>) -> Result<Object> {
    match tok {
        Token::Null => Ok(Object::Null),
        Token::Bool(b) => Ok(Object::Bool(b)),
        Token::Real(r) => Ok(Object::Real(r)),
        Token::Str(s) => Ok(Object::Str(s)),
        Token::Name(n) => Ok(Object::Name(n)),
        Token::Int(n) => maybe_reference(n, lex),
        Token::ArrayOpen => {
            let mut items = Vec::new();
            loop {
                let t = lex
                    .next_token()?
                    .ok_or_else(|| FormatError::Invalid("pdf: unexpected EOF in array".into()))?;
                if t == Token::ArrayClose {
                    break;
                }
                items.push(object_from_token(t, lex, doc)?);
            }
            Ok(Object::Array(items))
        }
        Token::DictOpen => parse_dict_or_stream(lex, doc),
        Token::Keyword(k) => Ok(Object::Keyword(k)),
        Token::ArrayClose => Err(FormatError::Invalid("pdf: unexpected ']'".into())),
        Token::DictClose => Err(FormatError::Invalid("pdf: unexpected '>>'".into())),
    }
}

/// On an `Int`, look ahead for `g R` (indirect reference); otherwise it is a
/// plain integer. The look-ahead never consumes tokens unless it commits.
fn maybe_reference(n: i64, lex: &mut Lexer) -> Result<Object> {
    let save = lex.pos;
    if let Ok(Some(Token::Int(g))) = lex.next_token() {
        let after_gen = lex.pos;
        if let Ok(Some(Token::Keyword(ref k))) = lex.next_token() {
            if k == b"R" && n >= 0 && (0..=u16::MAX as i64).contains(&g) {
                return Ok(Object::Ref(n as u32, g as u16));
            }
        }
        // `n g` but not `R`: rewind to just after the first int so `g` is
        // re-read as the next object.
        let _ = after_gen;
    }
    lex.pos = save;
    Ok(Object::Int(n))
}

/// After a `<<`, read `key value` pairs until `>>`, then check for a trailing
/// `stream` keyword promoting the dict to a stream object.
fn parse_dict_or_stream(lex: &mut Lexer, doc: Option<&PdfDocument>) -> Result<Object> {
    let mut dict = Dict::new();
    loop {
        let t = lex
            .next_token()?
            .ok_or_else(|| FormatError::Invalid("pdf: unexpected EOF in dict".into()))?;
        match t {
            Token::DictClose => break,
            Token::Name(key) => {
                let value = parse_object(lex, doc)?;
                dict.insert(key, value);
            }
            other => {
                return Err(FormatError::Invalid(format!(
                    "pdf: dict key must be a name, got {:?}",
                    other
                )));
            }
        }
    }
    // Peek for `stream`.
    let save = lex.pos;
    match lex.next_token()? {
        Some(Token::Keyword(ref k)) if k == b"stream" => parse_stream_body(dict, lex, doc),
        _ => {
            lex.pos = save;
            Ok(Object::Dict(dict))
        }
    }
}

/// Read a stream body. The cursor is positioned right after the `stream`
/// keyword; per the PDF spec the keyword is followed by CRLF or a single LF.
fn parse_stream_body(dict: Dict, lex: &mut Lexer, doc: Option<&PdfDocument>) -> Result<Object> {
    // Consume the single EOL after `stream`.
    if lex.peek() == Some(b'\r') {
        lex.pos += 1;
    }
    if lex.peek() == Some(b'\n') {
        lex.pos += 1;
    }
    let start = lex.pos;

    // Determine the raw length from /Length, resolving an indirect reference.
    let length = match dict.get("Length") {
        Some(Object::Int(n)) if *n >= 0 => Some(*n as usize),
        Some(Object::Ref(objid, _)) => match doc {
            Some(d) => d.get_object(*objid).ok().and_then(|o| match o {
                Object::Int(n) if n >= 0 => Some(n as usize),
                _ => None,
            }),
            None => None,
        },
        _ => None,
    };

    // Trust /Length when it lands exactly on an `endstream`; otherwise scan.
    let end = match length {
        Some(len) if start + len <= lex.data.len() && endstream_follows(lex.data, start + len) => {
            start + len
        }
        _ => find_endstream(lex.data, start)
            .ok_or_else(|| FormatError::Invalid("pdf: 'endstream' not found".into()))?,
    };

    let rawdata = lex.data[start..end].to_vec();

    // Advance past the trailing EOL + `endstream` keyword.
    lex.pos = end;
    lex.skip_ws();
    if lex.data[lex.pos..].starts_with(b"endstream") {
        lex.pos += b"endstream".len();
    }

    Ok(Object::Stream(PdfStream {
        dict,
        rawdata,
        objid: 0,
        genno: 0,
    }))
}

/// True if `endstream` appears at `pos` after at most one EOL of padding.
fn endstream_follows(data: &[u8], pos: usize) -> bool {
    let mut p = pos;
    if data.get(p) == Some(&b'\r') {
        p += 1;
    }
    if data.get(p) == Some(&b'\n') {
        p += 1;
    }
    data[p..].starts_with(b"endstream")
}

/// Scan forward for the `endstream` keyword, returning the offset of the byte
/// just before its preceding EOL (so the EOL is not part of the stream data).
fn find_endstream(data: &[u8], start: usize) -> Option<usize> {
    let needle = b"endstream";
    let mut i = start;
    while i + needle.len() <= data.len() {
        if data[i..].starts_with(needle) {
            let mut end = i;
            // Trim one preceding EOL (\r\n, \n, or \r).
            if end > start && data[end - 1] == b'\n' {
                end -= 1;
            }
            if end > start && data[end - 1] == b'\r' {
                end -= 1;
            }
            return Some(end);
        }
        i += 1;
    }
    None
}

//
// ─── Cross-reference tables ─────────────────────────────────────────────────
//

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

//
// ─── Document ───────────────────────────────────────────────────────────────
//

/// A parsed PDF document: the cross-reference chain, the merged trailer, and a
/// lazy object cache. Objects are parsed on demand via [`Self::get_object`].
pub struct PdfDocument {
    data: Vec<u8>,
    /// The `%PDF-x.y` header line (first 8 bytes), re-emitted verbatim.
    version: Vec<u8>,
    xrefs: Vec<XRef>,
    trailer: Dict,
    cache: RefCell<HashMap<u32, Object>>,
    objstm_cache: RefCell<HashMap<u32, Vec<Object>>>,
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
        };
        doc.read_xrefs()?;
        Ok(doc)
    }

    /// The union of all object ids reachable through the cross-reference chain.
    pub fn object_ids(&self) -> Vec<u32> {
        let mut ids: Vec<u32> = Vec::new();
        let mut seen = std::collections::HashSet::new();
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
        let entry = self
            .locate(objid)
            .ok_or_else(|| FormatError::Invalid(format!("pdf: object {} not found", objid)))?;
        let obj = match entry {
            XRefEntry::Uncompressed { offset } => self.parse_indirect_at(offset, objid)?,
            XRefEntry::InObjStm { stmid, index } => self.parse_from_objstm(stmid, index)?,
        };
        self.cache.borrow_mut().insert(objid, obj.clone());
        Ok(obj)
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
        let mut obj = parse_object(&mut lex, Some(self))?;
        if let Object::Stream(ref mut s) = obj {
            s.objid = objid;
            s.genno = genno.max(0) as u16;
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
            let data = stream.decoded()?;
            // The decoded stream is a flat token sequence: 2*N header integers
            // (objnum, offset pairs) followed by the N member objects.
            let mut lex = Lexer::new(&data);
            let mut objs = Vec::new();
            while let Some(tok) = lex.next_token()? {
                objs.push(object_from_token(tok, &mut lex, None)?);
            }
            self.objstm_cache.borrow_mut().insert(stmid, objs);
        }
        // /N members: the first 2*N entries are the header pairs, so member
        // `index` sits at flat position 2*N + index.
        let n = self
            .get_object(stmid)?
            .as_dict()
            .and_then(|d| d.get("N"))
            .and_then(Object::as_int)
            .unwrap_or(0)
            .max(0) as usize;
        let i = n * 2 + index;
        let borrow = self.objstm_cache.borrow();
        let objs = borrow.get(&stmid).ok_or_else(|| {
            FormatError::Invalid(format!("pdf: object stream {} vanished", stmid))
        })?;
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
        let mut visited = std::collections::HashSet::new();
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

    fn read_xref_from(
        &mut self,
        start: usize,
        visited: &mut std::collections::HashSet<usize>,
    ) -> Result<()> {
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
            let save = lex.pos;
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
                    let _ = save;
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

/// Read the next token expecting an integer.
fn expect_int(lex: &mut Lexer) -> Result<i64> {
    match lex.next_token()? {
        Some(Token::Int(n)) => Ok(n),
        other => Err(FormatError::Invalid(format!(
            "pdf: expected integer, got {:?}",
            other
        ))),
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

//
// ─── Stream decoding (filters + predictor) ──────────────────────────────────
//

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

    /// The `/DecodeParms` (or legacy `/DP`) dictionary, if any.
    fn decode_parms(&self) -> Option<&Dict> {
        self.dict
            .get("DP")
            .or_else(|| self.dict.get("DecodeParms"))
            .and_then(Object::as_dict)
    }

    /// Decode the raw stream body: apply each filter, then the predictor.
    ///
    /// This assumes the raw bytes are already decrypted (decryption happens in
    /// the scheme layer before filters). Names `Fl`/`LZW`/`A85` are accepted as
    /// abbreviations, matching `ineptpdf.py`.
    pub fn decoded(&self) -> Result<Vec<u8>> {
        let mut data = self.rawdata.clone();
        for f in self.filters() {
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
            if let Some(params) = self.decode_parms() {
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

//
// ─── Serializer ─────────────────────────────────────────────────────────────
//

/// Re-emits a `PdfDocument` as a clean, unencrypted PDF.
///
/// Mirrors `ineptpdf.PDFSerializer` in its default (classic-xref) mode:
/// generation numbers are forced to 0, `/Encrypt` is dropped, object streams
/// are dissolved (their members promoted to top-level objects and the container
/// replaced by a harmless placeholder), and a fresh classic `xref` table +
/// trailer are written.
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
            if is_type(&obj, "XRef") {
                continue;
            }
            offsets.insert(objid, out.len());
            out.extend_from_slice(format!("{} 0 obj", objid).as_bytes());
            if is_type(&obj, "ObjStm") {
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

/// True if an object's dictionary `/Type` is `name`.
fn is_type(obj: &Object, name: &str) -> bool {
    obj.as_dict()
        .and_then(|d| d.get("Type"))
        .and_then(Object::as_name)
        == Some(name)
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

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn tokens(data: &[u8]) -> Vec<Token> {
        let mut lex = Lexer::new(data);
        let mut out = Vec::new();
        while let Some(t) = lex.next_token().unwrap() {
            out.push(t);
        }
        out
    }

    #[test]
    fn lex_names_numbers_bools() {
        let t = tokens(b"/Type /Page 12 -3 2.5 true false null");
        assert_eq!(
            t,
            vec![
                Token::Name("Type".into()),
                Token::Name("Page".into()),
                Token::Int(12),
                Token::Int(-3),
                Token::Real(2.5),
                Token::Bool(true),
                Token::Bool(false),
                Token::Null,
            ]
        );
    }

    #[test]
    fn lex_name_hex_escape() {
        let t = tokens(b"/A#20B");
        assert_eq!(t, vec![Token::Name("A B".into())]);
    }

    #[test]
    fn lex_literal_string_escapes() {
        let t = tokens(b"(a\\(b\\)\\\\ \\n \\101)");
        assert_eq!(t, vec![Token::Str(b"a(b)\\ \n A".to_vec())]);
    }

    #[test]
    fn lex_hex_string() {
        let t = tokens(b"<48656C6C6F>");
        assert_eq!(t, vec![Token::Str(b"Hello".to_vec())]);
        // Odd digit is zero-padded.
        let t = tokens(b"<41f>");
        assert_eq!(t, vec![Token::Str(vec![0x41, 0xf0])]);
    }

    #[test]
    fn lex_dict_and_array_delims() {
        let t = tokens(b"<< /Kids [1 0 R] >>");
        assert_eq!(
            t,
            vec![
                Token::DictOpen,
                Token::Name("Kids".into()),
                Token::ArrayOpen,
                Token::Int(1),
                Token::Int(0),
                Token::Keyword(b"R".to_vec()),
                Token::ArrayClose,
                Token::DictClose,
            ]
        );
    }

    #[test]
    fn parse_indirect_reference() {
        let mut lex = Lexer::new(b"[1 0 R 42 2 0 R]");
        let obj = parse_object(&mut lex, None).unwrap();
        assert_eq!(
            obj,
            Object::Array(vec![Object::Ref(1, 0), Object::Int(42), Object::Ref(2, 0),])
        );
    }

    #[test]
    fn parse_nested_dict() {
        let mut lex = Lexer::new(b"<< /A 1 /B << /C [true (x)] >> >>");
        let obj = parse_object(&mut lex, None).unwrap();
        let d = obj.as_dict().unwrap();
        assert_eq!(d.get("A"), Some(&Object::Int(1)));
        let inner = d.get("B").unwrap().as_dict().unwrap();
        assert_eq!(
            inner.get("C"),
            Some(&Object::Array(vec![
                Object::Bool(true),
                Object::Str(b"x".to_vec())
            ]))
        );
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
        assert!(is_type(&catalog, "Catalog"));
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

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
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
        let objstm_data = {
            let mut d = Vec::new();
            d.extend_from_slice(header);
            let first = d.len();
            d.extend_from_slice(member);
            (d, first)
        };
        let (objstm_plain, first) = objstm_data;
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
        assert!(is_type(&catalog, "Catalog"));
        // Its /Pages reference resolves to the uncompressed object 3.
        let pages = doc
            .resolve(catalog.as_dict().unwrap().get("Pages").unwrap())
            .unwrap();
        assert!(is_type(&pages, "Pages"));
        // Trailer /Root comes from the xref stream dict.
        assert_eq!(doc.trailer().get("Root"), Some(&Object::Ref(1, 0)));
    }

    #[test]
    fn xref_stream_serializes_to_classic() {
        let pdf = build_xref_stream_pdf();
        let doc = PdfDocument::parse(&pdf).unwrap();
        let out = PdfSerializer::new(&doc).serialize().unwrap();
        // Re-parse: the output must be a classic-xref PDF (starts the xref with
        // the `xref` keyword) that still exposes the catalog and pages.
        let doc2 = PdfDocument::parse(&out).unwrap();
        let catalog = doc2.get_object(1).unwrap();
        assert!(is_type(&catalog, "Catalog"));
        let pages = doc2
            .resolve(catalog.as_dict().unwrap().get("Pages").unwrap())
            .unwrap();
        assert!(is_type(&pages, "Pages"));
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
}
