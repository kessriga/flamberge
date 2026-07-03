//! Amazon ION binary format — minimal pull parser for KFX voucher/content.
//!
//! Type descriptor byte = high nibble type-id, low nibble length (`0xE` = VarUInt
//! length, `0xF` = null). VarUInt/VarInt are big-endian base-128 with the
//! terminator flagged by a set high bit. A shared symbol table (`ProtectedData`)
//! must be pre-seeded so annotations resolve to names like
//! `com.amazon.drm.Voucher@1.0`.
//!
//! This is a faithful port of `ion.py::BinaryIonParser` — a pull parser driven by
//! [`BinaryIonParser::next`] / [`BinaryIonParser::step_in`] /
//! [`BinaryIonParser::step_out`], with scalar accessors that decode the current
//! value on demand. Scope is exactly what KFX vouchers and content need:
//! ints/symbols, UTF-8 strings, BLOB/CLOB, lists, structs, and annotations.
//! Float/decimal/timestamp values are recognised and skipped but not decoded.
//!
//! Reference: `docs/DEDRM_SCHEMES.md` §3.2. Original: `ion.py`.

use crate::{FormatError, Result};

pub const BVM: [u8; 4] = [0xE0, 0x01, 0x00, 0xEA];

// Type ids (high nibble of the descriptor byte). Kept as raw `i32` internally so
// `-1` can act as the "no current value / EOF" sentinel, matching `ion.py`.
const TID_NULL: i32 = 0x0;
const TID_BOOLEAN: i32 = 0x1;
const TID_POSINT: i32 = 0x2;
const TID_NEGINT: i32 = 0x3;
const TID_FLOAT: i32 = 0x4;
const TID_DECIMAL: i32 = 0x5;
const TID_TIMESTAMP: i32 = 0x6;
const TID_SYMBOL: i32 = 0x7;
const TID_STRING: i32 = 0x8;
const TID_CLOB: i32 = 0x9;
const TID_BLOB: i32 = 0xA;
const TID_LIST: i32 = 0xB;
const TID_SEXP: i32 = 0xC;
const TID_STRUCT: i32 = 0xD;
const TID_TYPEDECL: i32 = 0xE;

const LEN_IS_VAR_LEN: usize = 0xE;
const LEN_IS_NULL: usize = 0xF;

// System symbol ids (Ion 1.0). Imported/local symbols start after these.
const SID_UNKNOWN: i64 = -1;
const SID_ION: i64 = 1;
const SID_ION_1_0: i64 = 2;
const SID_ION_SYMBOL_TABLE: i64 = 3;
const SID_NAME: i64 = 4;
const SID_VERSION: i64 = 5;
const SID_IMPORTS: i64 = 6;
const SID_MAX_ID: i64 = 8;
/// Length of the seeded system symbol table (indices 0..=9; SIDs 1..=9 filled).
const SID_ION_1_0_MAX: usize = 10;

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
/// high bit set terminates. Returns `(value, bytes_consumed)`.
///
/// Big-endian base-128, at most 5 bytes (1 lead + 4 continuation); a longer
/// run without a terminator is a decode error. See §3.2.
pub fn read_varuint(data: &[u8]) -> Result<(u64, usize)> {
    let mut idx = 0usize;
    let mut b = byte_at(data, idx)?;
    idx += 1;
    let mut result = (b & 0x7F) as u64;
    let mut i = 0;
    while (b & 0x80) == 0 && i < 4 {
        b = byte_at(data, idx)?;
        idx += 1;
        result = (result << 7) | (b & 0x7F) as u64;
        i += 1;
    }
    if !(i < 4 || (b & 0x80) != 0) {
        return Err(FormatError::Invalid("ION VarUInt overflow".into()));
    }
    Ok((result, idx))
}

/// Read an ION VarInt. Same base-128 encoding as VarUInt, but the first byte's
/// `0x40` bit is the sign and `0x3F` holds the top magnitude bits. See §3.2.
pub fn read_varint(data: &[u8]) -> Result<(i64, usize)> {
    let mut idx = 0usize;
    let mut b = byte_at(data, idx)?;
    idx += 1;
    let negative = (b & 0x40) != 0;
    let mut result: i64 = (b & 0x3F) as i64;
    let mut i = 0;
    while (b & 0x80) == 0 && i < 4 {
        b = byte_at(data, idx)?;
        idx += 1;
        result = (result << 7) | (b & 0x7F) as i64;
        i += 1;
    }
    if !(i < 4 || (b & 0x80) != 0) {
        return Err(FormatError::Invalid("ION VarInt overflow".into()));
    }
    Ok((if negative { -result } else { result }, idx))
}

fn byte_at(data: &[u8], idx: usize) -> Result<u8> {
    data.get(idx).copied().ok_or(FormatError::Truncated(idx))
}

/// The fixed `ProtectedData` shared symbol table (`ion.py::SYM_NAMES`). Order is
/// positional and load-bearing: imported symbols are assigned sequential SIDs, so
/// annotations in real KFX streams resolve to these names only if the ordering is
/// preserved exactly. The tail is the programmatically appended
/// `com.amazon.drm.VoucherEnvelope@{2..=28}.0` followed by a fixed set of numeric
/// versions. See §3.2.
pub fn protected_data_symbols() -> Vec<String> {
    const BASE: &[&str] = &[
        "com.amazon.drm.Envelope@1.0",
        "com.amazon.drm.EnvelopeMetadata@1.0",
        "size",
        "page_size",
        "encryption_key",
        "encryption_transformation",
        "encryption_voucher",
        "signing_key",
        "signing_algorithm",
        "signing_voucher",
        "com.amazon.drm.EncryptedPage@1.0",
        "cipher_text",
        "cipher_iv",
        "com.amazon.drm.Signature@1.0",
        "data",
        "com.amazon.drm.EnvelopeIndexTable@1.0",
        "length",
        "offset",
        "algorithm",
        "encoded",
        "encryption_algorithm",
        "hashing_algorithm",
        "expires",
        "format",
        "id",
        "lock_parameters",
        "strategy",
        "com.amazon.drm.Key@1.0",
        "com.amazon.drm.KeySet@1.0",
        "com.amazon.drm.PIDv3@1.0",
        "com.amazon.drm.PlainTextPage@1.0",
        "com.amazon.drm.PlainText@1.0",
        "com.amazon.drm.PrivateKey@1.0",
        "com.amazon.drm.PublicKey@1.0",
        "com.amazon.drm.SecretKey@1.0",
        "com.amazon.drm.Voucher@1.0",
        "public_key",
        "private_key",
        "com.amazon.drm.KeyPair@1.0",
        "com.amazon.drm.ProtectedData@1.0",
        "doctype",
        "com.amazon.drm.EnvelopeIndexTableOffset@1.0",
        "enddoc",
        "license_type",
        "license",
        "watermark",
        "key",
        "value",
        "com.amazon.drm.License@1.0",
        "category",
        "metadata",
        "categorized_metadata",
        "com.amazon.drm.CategorizedMetadata@1.0",
        "com.amazon.drm.VoucherEnvelope@1.0",
        "mac",
        "voucher",
        "com.amazon.drm.ProtectedData@2.0",
        "com.amazon.drm.Envelope@2.0",
        "com.amazon.drm.EnvelopeMetadata@2.0",
        "com.amazon.drm.EncryptedPage@2.0",
        "com.amazon.drm.PlainText@2.0",
        "compression_algorithm",
        "com.amazon.drm.Compressed@1.0",
        "page_index_table",
    ];
    const EXTRA_VERSIONS: &[u32] = &[9708, 1031, 2069, 9041, 3646, 6052, 9479, 9888, 4648, 5683];

    let mut names: Vec<String> = BASE.iter().map(|s| (*s).to_owned()).collect();
    for n in 2..=28u32 {
        names.push(format!("com.amazon.drm.VoucherEnvelope@{n}.0"));
    }
    for &n in EXTRA_VERSIONS {
        names.push(format!("com.amazon.drm.VoucherEnvelope@{n}.0"));
    }
    names
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ParserState {
    BeforeField,
    BeforeTid,
    BeforeValue,
    AfterValue,
    Eof,
}

#[derive(Clone, Copy)]
struct ContainerRec {
    /// Absolute position of the byte just past this container.
    nextpos: usize,
    /// Parent container's `parenttid`, restored on step-out.
    tid: i32,
    /// Parent's remaining byte budget, restored on step-out.
    remaining: i64,
}

#[derive(Clone)]
enum ScalarValue {
    Int(i64),
    Text(String),
}

#[derive(Clone)]
struct IonCatalogItem {
    name: String,
    version: i64,
    symnames: Vec<String>,
}

/// The parser's symbol table: system symbols plus any imported/local symbols.
struct SymbolTable {
    table: Vec<Option<String>>,
}

impl SymbolTable {
    fn new() -> Self {
        let mut table = vec![None; SID_ION_1_0_MAX];
        table[SID_ION as usize] = Some("$ion".into());
        table[SID_ION_1_0 as usize] = Some("$ion_1_0".into());
        table[SID_ION_SYMBOL_TABLE as usize] = Some("$ion_symbol_table".into());
        table[SID_NAME as usize] = Some("name".into());
        table[SID_VERSION as usize] = Some("version".into());
        table[SID_IMPORTS as usize] = Some("imports".into());
        table[7] = Some("symbols".into());
        table[SID_MAX_ID as usize] = Some("max_id".into());
        table[9] = Some("$ion_shared_symbol_table".into());
        Self { table }
    }

    fn find_by_id(&self, sid: i64) -> String {
        if sid < 1 {
            return String::new();
        }
        match self.table.get(sid as usize) {
            Some(Some(name)) => name.clone(),
            _ => String::new(),
        }
    }

    fn import(&mut self, item: &IonCatalogItem, maxid: usize) {
        for name in item.symnames.iter().take(maxid) {
            self.table.push(Some(name.clone()));
        }
    }

    fn import_unknown(&mut self, name: &str, maxid: usize) {
        for i in 0..maxid {
            self.table.push(Some(format!("{name}#{}", i + 1)));
        }
    }
}

/// Amazon ION binary pull parser over a borrowed byte stream.
///
/// Lifecycle mirrors `ion.py`: call [`BinaryIonParser::next`] to advance to the
/// next value (returns `None` at end / container boundary), inspect it with
/// [`BinaryIonParser::type_name`] / [`BinaryIonParser::field_name`], read scalars
/// with the `*_value` accessors, and use [`BinaryIonParser::step_in`] /
/// [`BinaryIonParser::step_out`] to descend into lists and structs. Seed the
/// shared table with [`BinaryIonParser::add_protected_data_table`] before parsing
/// KFX vouchers/content so their annotations resolve.
pub struct BinaryIonParser<'a> {
    data: &'a [u8],
    pos: usize,
    initpos: usize,
    state: ParserState,
    /// Remaining byte budget for the current container; `-1` = unbounded (top).
    localremaining: i64,
    needhasnext: bool,
    eof: bool,
    isinstruct: bool,
    valuetid: i32,
    valuefieldid: i64,
    parenttid: i32,
    valuelen: usize,
    valueisnull: bool,
    valueistrue: bool,
    value: Option<ScalarValue>,
    annotations: Vec<i64>,
    containerstack: Vec<ContainerRec>,
    symbols: SymbolTable,
    catalog: Vec<IonCatalogItem>,
    didimports: bool,
}

impl<'a> BinaryIonParser<'a> {
    /// Create a parser positioned at the start of `data`.
    pub fn new(data: &'a [u8]) -> Self {
        BinaryIonParser {
            data,
            pos: 0,
            initpos: 0,
            state: ParserState::BeforeTid,
            localremaining: -1,
            needhasnext: true,
            eof: false,
            isinstruct: false,
            valuetid: -1,
            valuefieldid: SID_UNKNOWN,
            parenttid: 0,
            valuelen: 0,
            valueisnull: false,
            valueistrue: false,
            value: None,
            annotations: Vec::new(),
            containerstack: Vec::new(),
            symbols: SymbolTable::new(),
            catalog: Vec::new(),
            didimports: false,
        }
    }

    /// Register a shared symbol table so a stream's local table can import it by
    /// name (see [`IonCatalogItem`] resolution in `read_import`).
    pub fn add_to_catalog(&mut self, name: &str, version: i64, symnames: Vec<String>) {
        self.catalog.push(IonCatalogItem {
            name: name.to_owned(),
            version,
            symnames,
        });
    }

    /// Seed the catalog with the `ProtectedData` v1 shared table (§3.2). Required
    /// before parsing any KFX voucher/content stream.
    pub fn add_protected_data_table(&mut self) {
        self.add_to_catalog("ProtectedData", 1, protected_data_symbols());
    }

    /// Rewind to the start; keeps the symbol table and catalog intact.
    pub fn reset(&mut self) {
        self.state = ParserState::BeforeTid;
        self.needhasnext = true;
        self.localremaining = -1;
        self.eof = false;
        self.isinstruct = false;
        self.containerstack.clear();
        self.pos = self.initpos;
        self.clear_value();
    }

    /// Advance to the next value. Returns its [`TypeId`], or `None` at the end of
    /// the stream or current container.
    ///
    /// Named `next` to mirror the `ion.py` pull-parser API; it is not an
    /// [`Iterator`] (it borrows `&mut self` and yields a fallible type id).
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<TypeId>> {
        let tid = self.next_tid()?;
        Ok(if tid < 0 {
            None
        } else {
            Some(TypeId::from_nibble(tid as u8))
        })
    }

    /// Step into the current list, sexp, or struct so subsequent
    /// [`BinaryIonParser::next`] calls iterate its children.
    pub fn step_in(&mut self) -> Result<()> {
        if self.eof
            || !(self.valuetid == TID_STRUCT
                || self.valuetid == TID_LIST
                || self.valuetid == TID_SEXP)
        {
            return Err(FormatError::Invalid(
                "ION step_in requires a container".into(),
            ));
        }
        let state_ok = (!self.valueisnull || self.state == ParserState::AfterValue)
            && (self.valueisnull || self.state == ParserState::BeforeValue);
        if !state_ok {
            return Err(FormatError::Invalid("ION step_in in invalid state".into()));
        }

        let mut nextrem = self.localremaining;
        if nextrem != -1 {
            nextrem -= self.valuelen as i64;
            if nextrem < 0 {
                nextrem = 0;
            }
        }
        let nextpos = self.pos + self.valuelen;
        self.containerstack.push(ContainerRec {
            nextpos,
            tid: self.parenttid,
            remaining: nextrem,
        });

        self.isinstruct = self.valuetid == TID_STRUCT;
        self.state = if self.isinstruct {
            ParserState::BeforeField
        } else {
            ParserState::BeforeTid
        };
        self.localremaining = self.valuelen as i64;
        self.parenttid = self.valuetid;
        self.clear_value();
        self.needhasnext = true;
        Ok(())
    }

    /// Step out of the current container, skipping any unread remainder.
    pub fn step_out(&mut self) -> Result<()> {
        let rec = self
            .containerstack
            .pop()
            .ok_or(FormatError::Invalid("ION step_out without step_in".into()))?;

        self.eof = false;
        self.parenttid = rec.tid;
        self.isinstruct = self.parenttid == TID_STRUCT;
        self.state = if self.isinstruct {
            ParserState::BeforeField
        } else {
            ParserState::BeforeTid
        };
        self.needhasnext = true;
        self.clear_value();

        if rec.nextpos > self.pos {
            let skip = rec.nextpos - self.pos;
            self.skip(skip)?;
        } else if rec.nextpos != self.pos {
            return Err(FormatError::Invalid(
                "ION step_out position mismatch".into(),
            ));
        }
        self.localremaining = rec.remaining;
        Ok(())
    }

    /// Name of the current value's first annotation (its "type name"), or empty.
    pub fn type_name(&self) -> String {
        match self.annotations.first() {
            Some(&sid) => self.symbols.find_by_id(sid),
            None => String::new(),
        }
    }

    /// Field name of the current value when iterating a struct, or empty.
    pub fn field_name(&self) -> String {
        if self.valuefieldid == SID_UNKNOWN {
            String::new()
        } else {
            self.symbols.find_by_id(self.valuefieldid)
        }
    }

    /// Whether the current value is an ION null.
    pub fn is_null(&self) -> bool {
        self.valueisnull
    }

    /// Value of the current boolean (meaningful only after a bool `next`).
    pub fn bool_value(&self) -> bool {
        self.valueistrue
    }

    /// Decode the current int/symbol as a signed big-endian magnitude.
    pub fn int_value(&mut self) -> Result<i64> {
        if self.valuetid != TID_POSINT && self.valuetid != TID_NEGINT {
            return Err(FormatError::Invalid("ION value is not an int".into()));
        }
        self.prepare_value()?;
        Ok(match self.value {
            Some(ScalarValue::Int(v)) => v,
            _ => 0,
        })
    }

    /// Decode the current string as UTF-8.
    pub fn string_value(&mut self) -> Result<String> {
        if self.valuetid != TID_STRING {
            return Err(FormatError::Invalid("ION value is not a string".into()));
        }
        if self.valueisnull {
            return Ok(String::new());
        }
        self.prepare_value()?;
        Ok(match &self.value {
            Some(ScalarValue::Text(s)) => s.clone(),
            _ => String::new(),
        })
    }

    /// Resolve the current symbol value to its name (or `SYMBOL#<sid>`).
    pub fn symbol_value(&mut self) -> Result<String> {
        if self.valuetid != TID_SYMBOL {
            return Err(FormatError::Invalid("ION value is not a symbol".into()));
        }
        self.prepare_value()?;
        let sid = match self.value {
            Some(ScalarValue::Int(v)) => v,
            _ => 0,
        };
        let name = self.symbols.find_by_id(sid);
        Ok(if name.is_empty() {
            format!("SYMBOL#{sid}")
        } else {
            name
        })
    }

    /// Return the raw bytes of the current BLOB/CLOB, or `None` if null.
    pub fn lob_value(&mut self) -> Result<Option<Vec<u8>>> {
        if self.valuetid != TID_CLOB && self.valuetid != TID_BLOB {
            return Err(FormatError::Invalid("ION value is not a LOB".into()));
        }
        if self.valueisnull {
            return Ok(None);
        }
        let bytes = self.read(self.valuelen)?.to_vec();
        self.state = ParserState::AfterValue;
        Ok(Some(bytes))
    }

    // --- internals ---

    fn next_tid(&mut self) -> Result<i32> {
        if self.has_next()? {
            self.needhasnext = true;
            Ok(self.valuetid)
        } else {
            Ok(-1)
        }
    }

    fn has_next(&mut self) -> Result<bool> {
        while self.needhasnext && !self.eof {
            self.has_next_raw()?;
            if self.containerstack.is_empty() && !self.valueisnull {
                if self.valuetid == TID_SYMBOL {
                    if let Some(ScalarValue::Int(v)) = self.value {
                        if v == SID_ION_1_0 {
                            self.needhasnext = true;
                        }
                    }
                } else if self.valuetid == TID_STRUCT
                    && self.annotations.contains(&SID_ION_SYMBOL_TABLE)
                {
                    self.parse_symbol_table()?;
                    self.needhasnext = true;
                }
            }
        }
        Ok(!self.eof)
    }

    fn has_next_raw(&mut self) -> Result<()> {
        self.clear_value();
        while self.valuetid == -1 && !self.eof {
            self.needhasnext = false;
            match self.state {
                ParserState::BeforeField => {
                    self.valuefieldid = self.read_field_id()?;
                    if self.valuefieldid != SID_UNKNOWN {
                        self.state = ParserState::BeforeTid;
                    } else {
                        self.eof = true;
                    }
                }
                ParserState::BeforeTid => {
                    self.state = ParserState::BeforeValue;
                    self.valuetid = self.read_type_id()?;
                    if self.valuetid == -1 {
                        self.state = ParserState::Eof;
                        self.eof = true;
                        break;
                    }
                    if self.valuetid == TID_TYPEDECL {
                        if self.valuelen == 0 {
                            self.check_version_marker()?;
                        } else {
                            self.load_annotations()?;
                        }
                    }
                }
                ParserState::BeforeValue => {
                    self.skip(self.valuelen)?;
                    self.state = ParserState::AfterValue;
                }
                ParserState::AfterValue => {
                    self.state = if self.isinstruct {
                        ParserState::BeforeField
                    } else {
                        ParserState::BeforeTid
                    };
                }
                ParserState::Eof => break,
            }
        }
        Ok(())
    }

    /// Read `count` bytes, decrementing the container budget. Returns a slice
    /// borrowed from the underlying stream (lifetime `'a`).
    fn read(&mut self, count: usize) -> Result<&'a [u8]> {
        if self.localremaining != -1 {
            self.localremaining -= count as i64;
            if self.localremaining < 0 {
                return Err(FormatError::Invalid(
                    "ION read past container budget".into(),
                ));
            }
        }
        let end = self
            .pos
            .checked_add(count)
            .ok_or(FormatError::Truncated(self.pos))?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or(FormatError::Truncated(self.pos))?;
        self.pos = end;
        Ok(slice)
    }

    fn skip(&mut self, count: usize) -> Result<()> {
        if self.localremaining != -1 {
            self.localremaining -= count as i64;
            if self.localremaining < 0 {
                return Err(FormatError::Truncated(self.pos));
            }
        }
        let end = self
            .pos
            .checked_add(count)
            .ok_or(FormatError::Truncated(self.pos))?;
        if end > self.data.len() {
            return Err(FormatError::Truncated(self.pos));
        }
        self.pos = end;
        Ok(())
    }

    fn read_varuint_stream(&mut self) -> Result<u64> {
        let rem = self.data.get(self.pos..).unwrap_or(&[]);
        let (value, consumed) = read_varuint(rem)?;
        self.read(consumed)?;
        Ok(value)
    }

    fn read_field_id(&mut self) -> Result<i64> {
        if self.localremaining != -1 && self.localremaining < 1 {
            return Ok(SID_UNKNOWN);
        }
        match self.read_varuint_stream() {
            Ok(v) => Ok(v as i64),
            // A clean end-of-data mid-field id means "no more fields".
            Err(FormatError::Truncated(_)) => Ok(SID_UNKNOWN),
            Err(e) => Err(e),
        }
    }

    fn read_type_id(&mut self) -> Result<i32> {
        if self.localremaining != -1 {
            if self.localremaining < 1 {
                return Ok(-1);
            }
            self.localremaining -= 1;
        }
        let b = match self.data.get(self.pos) {
            Some(&b) => b,
            None => return Ok(-1),
        };
        self.pos += 1;

        let result = (b >> 4) as i32;
        let mut ln = (b & 0x0F) as usize;

        if ln == LEN_IS_VAR_LEN {
            ln = self.read_varuint_stream()? as usize;
        } else if ln == LEN_IS_NULL {
            // Null of this type: no payload. (We flag null-ness here even though
            // ion.py leaves it implicit; it makes `is_null()` meaningful and does
            // not affect the non-null KFX paths.)
            ln = 0;
            self.valueisnull = true;
            self.state = ParserState::AfterValue;
        } else if result == TID_NULL {
            return Err(FormatError::Invalid(
                "ION null without null length nibble".into(),
            ));
        } else if result == TID_BOOLEAN {
            if ln > 1 {
                return Err(FormatError::Invalid(
                    "ION bool length must be 0 or 1".into(),
                ));
            }
            self.valueistrue = ln == 1;
            ln = 0;
            self.state = ParserState::AfterValue;
        } else if result == TID_STRUCT && ln == 1 {
            // L==1 struct is the ordered-struct special: real length follows.
            ln = self.read_varuint_stream()? as usize;
        }

        self.valuelen = ln;
        Ok(result)
    }

    fn load_annotations(&mut self) -> Result<()> {
        let ann_len = self.read_varuint_stream()? as usize;
        let maxpos = self.pos + ann_len;
        while self.pos < maxpos {
            let sid = self.read_varuint_stream()?;
            self.annotations.push(sid as i64);
        }
        self.valuetid = self.read_type_id()?;
        Ok(())
    }

    fn check_version_marker(&mut self) -> Result<()> {
        for &want in &[0x01u8, 0x00, 0xEA] {
            let got = self.read(1)?;
            if got[0] != want {
                return Err(FormatError::Invalid("ION unknown version marker".into()));
            }
        }
        self.valuelen = 0;
        self.valuetid = TID_SYMBOL;
        self.value = Some(ScalarValue::Int(SID_ION_1_0));
        self.valueisnull = false;
        self.valuefieldid = SID_UNKNOWN;
        self.state = ParserState::AfterValue;
        Ok(())
    }

    fn clear_value(&mut self) {
        self.valuetid = -1;
        self.value = None;
        self.valueisnull = false;
        self.valuefieldid = SID_UNKNOWN;
        self.annotations.clear();
    }

    fn prepare_value(&mut self) -> Result<()> {
        if self.value.is_none() {
            self.load_scalar_value()?;
        }
        Ok(())
    }

    fn load_scalar_value(&mut self) -> Result<()> {
        match self.valuetid {
            TID_NULL | TID_BOOLEAN | TID_POSINT | TID_NEGINT | TID_FLOAT | TID_DECIMAL
            | TID_TIMESTAMP | TID_SYMBOL | TID_STRING => {}
            _ => return Ok(()),
        }
        if self.valueisnull {
            self.value = None;
            return Ok(());
        }

        if self.valuetid == TID_STRING {
            let bytes = self.read(self.valuelen)?;
            let text = std::str::from_utf8(bytes)
                .map_err(|_| FormatError::Invalid("ION string is not valid UTF-8".into()))?
                .to_owned();
            self.value = Some(ScalarValue::Text(text));
            self.state = ParserState::AfterValue;
        } else if self.valuetid == TID_POSINT
            || self.valuetid == TID_NEGINT
            || self.valuetid == TID_SYMBOL
        {
            if self.valuelen == 0 {
                self.value = Some(ScalarValue::Int(0));
            } else {
                if self.valuelen > 4 {
                    return Err(FormatError::Invalid("ION int magnitude too long".into()));
                }
                let bytes = self.read(self.valuelen)?;
                let mut v: i64 = 0;
                for &byte in bytes {
                    v = (v << 8) | byte as i64;
                }
                self.value = Some(ScalarValue::Int(if self.valuetid == TID_NEGINT {
                    -v
                } else {
                    v
                }));
            }
            self.state = ParserState::AfterValue;
        }
        // float/decimal/timestamp: not needed for KFX — left for the skip path.
        Ok(())
    }

    fn parse_symbol_table(&mut self) -> Result<()> {
        self.next_tid()?; // realise the current struct (no-op advance)
        if self.valuetid != TID_STRUCT {
            return Err(FormatError::Invalid(
                "ION symbol table is not a struct".into(),
            ));
        }
        if self.didimports {
            return Ok(());
        }

        self.step_in()?;
        let mut fieldtype = self.next_tid()?;
        while fieldtype != -1 {
            if !self.valueisnull {
                if self.valuefieldid != SID_IMPORTS {
                    return Err(FormatError::Invalid(
                        "ION unsupported symbol table field".into(),
                    ));
                }
                if fieldtype == TID_LIST {
                    self.gather_imports()?;
                }
            }
            fieldtype = self.next_tid()?;
        }
        self.step_out()?;
        self.didimports = true;
        Ok(())
    }

    fn gather_imports(&mut self) -> Result<()> {
        self.step_in()?;
        let mut t = self.next_tid()?;
        while t != -1 {
            if !self.valueisnull && t == TID_STRUCT {
                self.read_import()?;
            }
            t = self.next_tid()?;
        }
        self.step_out()
    }

    fn read_import(&mut self) -> Result<()> {
        let mut version: i64 = -1;
        let mut maxid: i64 = -1;
        let mut name = String::new();

        self.step_in()?;
        let mut t = self.next_tid()?;
        while t != -1 {
            if !self.valueisnull && self.valuefieldid != SID_UNKNOWN {
                match self.valuefieldid {
                    SID_NAME => name = self.string_value()?,
                    SID_VERSION => version = self.int_value()?,
                    SID_MAX_ID => maxid = self.int_value()?,
                    _ => {}
                }
            }
            t = self.next_tid()?;
        }
        self.step_out()?;

        if name.is_empty() || name == "$ion" {
            return Ok(());
        }
        if version < 1 {
            version = 1;
        }

        let found = self.catalog.iter().position(|c| c.name == name);
        let maxid = if maxid < 0 {
            match found {
                Some(i) if self.catalog[i].version == version => {
                    self.catalog[i].symnames.len() as i64
                }
                _ => {
                    return Err(FormatError::Invalid(format!(
                        "ION import {name} lacks max_id"
                    )))
                }
            }
        } else {
            maxid
        };
        let maxid = maxid.max(0) as usize;

        match found {
            Some(i) => {
                let item = self.catalog[i].clone();
                let symlen = item.symnames.len();
                self.symbols.import(&item, maxid.min(symlen));
                if symlen < maxid {
                    self.symbols
                        .import_unknown(&format!("{name}-unknown"), maxid - symlen);
                }
            }
            None => self.symbols.import_unknown(&name, maxid),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- ION encoder helpers (test-only): build byte streams from values so the
    // hand-built fixtures stay readable and derived straight from §3.2. ---

    fn varuint(mut n: u64) -> Vec<u8> {
        let mut groups = vec![(n & 0x7F) as u8];
        n >>= 7;
        while n > 0 {
            groups.push((n & 0x7F) as u8);
            n >>= 7;
        }
        groups.reverse();
        let last = groups.len() - 1;
        groups[last] |= 0x80; // terminator: high bit set on final byte
        groups
    }

    fn typed(tid: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let len = body.len();
        // struct with L==1 is the "ordered struct" special, so force var-len.
        let var_len = len >= 14 || (tid == 0xD && len == 1);
        if var_len {
            out.push((tid << 4) | 0x0E);
            out.extend(varuint(len as u64));
        } else {
            out.push((tid << 4) | (len as u8));
        }
        out.extend_from_slice(body);
        out
    }

    fn e_string(s: &str) -> Vec<u8> {
        typed(0x8, s.as_bytes())
    }

    fn e_blob(b: &[u8]) -> Vec<u8> {
        typed(0xA, b)
    }

    fn e_posint(mut n: u64) -> Vec<u8> {
        if n == 0 {
            return typed(0x2, &[]);
        }
        let mut bytes = Vec::new();
        while n > 0 {
            bytes.push((n & 0xFF) as u8);
            n >>= 8;
        }
        bytes.reverse();
        typed(0x2, &bytes)
    }

    fn e_field(sid: u64, val: &[u8]) -> Vec<u8> {
        let mut out = varuint(sid);
        out.extend_from_slice(val);
        out
    }

    fn e_struct(fields: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        for f in fields {
            body.extend_from_slice(f);
        }
        typed(0xD, &body)
    }

    fn e_list(items: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        for i in items {
            body.extend_from_slice(i);
        }
        typed(0xB, &body)
    }

    fn e_annot(sids: &[u64], val: &[u8]) -> Vec<u8> {
        let mut sid_bytes = Vec::new();
        for &s in sids {
            sid_bytes.extend(varuint(s));
        }
        let mut body = varuint(sid_bytes.len() as u64);
        body.extend(sid_bytes);
        body.extend_from_slice(val);
        typed(0xE, &body)
    }

    fn bvm() -> Vec<u8> {
        vec![0xE0, 0x01, 0x00, 0xEA]
    }

    // --- VarUInt / VarInt ---

    #[test]
    fn varuint_single_byte() {
        assert_eq!(read_varuint(&[0x8E]).unwrap(), (14, 1));
    }

    #[test]
    fn varuint_multi_byte() {
        // 128 = 0x01 0x80 (base-128, high bit set on terminator).
        assert_eq!(read_varuint(&[0x01, 0x80]).unwrap(), (128, 2));
    }

    #[test]
    fn varint_sign_bit() {
        // 0xC1 = sign(0x40) | magnitude 1 | terminator(0x80) => -1.
        assert_eq!(read_varint(&[0xC1]).unwrap(), (-1, 1));
        // 0x81 = magnitude 1, no sign => +1.
        assert_eq!(read_varint(&[0x81]).unwrap(), (1, 1));
    }

    // --- Symbol table ---

    #[test]
    fn protected_data_table_is_seeded() {
        let syms = protected_data_symbols();
        assert!(syms.iter().any(|s| s == "com.amazon.drm.Voucher@1.0"));
        assert!(syms
            .iter()
            .any(|s| s == "com.amazon.drm.VoucherEnvelope@28.0"));
        assert_eq!(
            syms.last().unwrap(),
            "com.amazon.drm.VoucherEnvelope@5683.0"
        );
        assert!(syms.len() > 70);
    }

    // --- Full parse: symbol table import + annotation + nested list + BLOB ---

    #[test]
    fn parse_struct_with_annotation_list_and_blob() {
        let syms = protected_data_symbols();
        // Imported symbols are appended starting at SID 10 (system symbols 1-9).
        let sid = |name: &str| 10u64 + syms.iter().position(|s| s == name).unwrap() as u64;

        // Local symbol table that imports the shared "ProtectedData" table.
        let directive = e_annot(
            &[3], // $ion_symbol_table
            &e_struct(&[e_field(
                6, // imports
                &e_list(&[e_struct(&[
                    e_field(4, &e_string("ProtectedData")),   // name
                    e_field(5, &e_posint(1)),                 // version
                    e_field(8, &e_posint(syms.len() as u64)), // max_id
                ])]),
            )]),
        );

        // A Voucher struct: a BLOB field and a nested annotated list.
        let value = e_annot(
            &[sid("com.amazon.drm.Voucher@1.0")],
            &e_struct(&[
                e_field(sid("voucher"), &e_blob(&[1, 2, 3])),
                e_field(
                    sid("license"),
                    &e_annot(
                        &[sid("com.amazon.drm.KeySet@1.0")],
                        &e_list(&[e_posint(7), e_posint(8)]),
                    ),
                ),
            ]),
        );

        let mut data = bvm();
        data.extend(directive);
        data.extend(value);

        let mut p = BinaryIonParser::new(&data);
        p.add_protected_data_table();

        assert_eq!(p.next().unwrap(), Some(TypeId::Struct));
        assert_eq!(p.type_name(), "com.amazon.drm.Voucher@1.0");

        p.step_in().unwrap();

        assert_eq!(p.next().unwrap(), Some(TypeId::Blob));
        assert_eq!(p.field_name(), "voucher");
        assert_eq!(p.lob_value().unwrap(), Some(vec![1, 2, 3]));

        assert_eq!(p.next().unwrap(), Some(TypeId::List));
        assert_eq!(p.field_name(), "license");
        assert_eq!(p.type_name(), "com.amazon.drm.KeySet@1.0");

        p.step_in().unwrap();
        assert_eq!(p.next().unwrap(), Some(TypeId::PosInt));
        assert_eq!(p.int_value().unwrap(), 7);
        assert_eq!(p.next().unwrap(), Some(TypeId::PosInt));
        assert_eq!(p.int_value().unwrap(), 8);
        assert_eq!(p.next().unwrap(), None);
        p.step_out().unwrap();

        assert_eq!(p.next().unwrap(), None);
        p.step_out().unwrap();
    }

    #[test]
    fn parse_top_level_scalars() {
        let mut data = bvm();
        data.extend(e_posint(258)); // 0x0102, big-endian magnitude
        let mut p = BinaryIonParser::new(&data);
        assert_eq!(p.next().unwrap(), Some(TypeId::PosInt));
        assert_eq!(p.int_value().unwrap(), 258);

        let mut data = bvm();
        data.extend(e_string("hi"));
        let mut p = BinaryIonParser::new(&data);
        assert_eq!(p.next().unwrap(), Some(TypeId::String));
        assert_eq!(p.string_value().unwrap(), "hi");
    }

    #[test]
    fn negint_symbol_and_null_values() {
        let syms = protected_data_symbols();
        let sid = |name: &str| 10u64 + syms.iter().position(|s| s == name).unwrap() as u64;

        // A struct: a negint, a symbol (resolving via the imported table), and a
        // typed null. Reuse the same import directive shape as the main test.
        let directive = e_annot(
            &[3],
            &e_struct(&[e_field(
                6,
                &e_list(&[e_struct(&[
                    e_field(4, &e_string("ProtectedData")),
                    e_field(5, &e_posint(1)),
                    e_field(8, &e_posint(syms.len() as u64)),
                ])]),
            )]),
        );

        let neg = typed(0x3, &[0x01, 0x02]); // negint magnitude 258 => -258
        let sym = typed(0x7, &[sid("voucher") as u8]); // symbol pointing at "voucher"
        let null_string = vec![0x8F]; // null.string
        let value = e_struct(&[e_field(4, &neg), e_field(5, &sym), e_field(6, &null_string)]);

        let mut data = bvm();
        data.extend(directive);
        data.extend(value);

        let mut p = BinaryIonParser::new(&data);
        p.add_protected_data_table();

        assert_eq!(p.next().unwrap(), Some(TypeId::Struct));
        p.step_in().unwrap();

        assert_eq!(p.next().unwrap(), Some(TypeId::NegInt));
        assert_eq!(p.int_value().unwrap(), -258);

        assert_eq!(p.next().unwrap(), Some(TypeId::Symbol));
        assert_eq!(p.symbol_value().unwrap(), "voucher");

        assert_eq!(p.next().unwrap(), Some(TypeId::String));
        assert!(p.is_null());
        assert_eq!(p.string_value().unwrap(), "");

        assert_eq!(p.next().unwrap(), None);
        p.step_out().unwrap();
    }

    #[test]
    fn struct_field_ids_resolve_system_symbols() {
        // A struct with a single "name" (SID 4) field, using only system symbols.
        let data = {
            let mut d = bvm();
            d.extend(e_struct(&[e_field(4, &e_string("x"))]));
            d
        };
        let mut p = BinaryIonParser::new(&data);
        assert_eq!(p.next().unwrap(), Some(TypeId::Struct));
        p.step_in().unwrap();
        assert_eq!(p.next().unwrap(), Some(TypeId::String));
        assert_eq!(p.field_name(), "name");
        assert_eq!(p.string_value().unwrap(), "x");
        assert_eq!(p.next().unwrap(), None);
        p.step_out().unwrap();
    }
}
