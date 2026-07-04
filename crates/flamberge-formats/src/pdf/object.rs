//! The parsed PDF object model: [`Object`], [`PdfStream`], and [`Dict`].
//!
//! This module is pure data — no I/O, no decoding. Stream decoding lives in
//! [`super::filters`]; parsing in [`super::parser`].

use std::collections::BTreeMap;

/// A PDF dictionary: name → object. Keys are stored without the leading `/`.
///
/// A `BTreeMap` gives deterministic serialization order; PDF dictionaries are
/// unordered, so this loses no information.
pub type Dict = BTreeMap<String, Object>;

/// A parsed PDF object.
///
/// `Ref(objid, genno)` is an *unresolved* indirect reference; call
/// [`PdfDocument::resolve`](super::PdfDocument::resolve) (or
/// [`PdfDocument::get_object`](super::PdfDocument::get_object)) to follow it.
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
/// Decoding (filters, predictor) is done on demand by
/// [`PdfStream::decoded`](super::PdfStream::decoded); the raw bytes are what a
/// decryptor operates on before filters are applied.
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

    /// The dictionary `/Type` name, if this object has one.
    pub fn type_name(&self) -> Option<&str> {
        self.as_dict()
            .and_then(|d| d.get("Type"))
            .and_then(Object::as_name)
    }
}
