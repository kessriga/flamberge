//! The recursive-descent object parser: [`Token`]s → [`Object`]s.
//!
//! The two document-aware entry points ([`parse_object`], [`object_from_token`])
//! take an optional [`PdfDocument`] so a stream's indirect `/Length` can be
//! resolved while reading its body. [`expect_int`] is a small helper shared with
//! the cross-reference readers in [`super::document`].

use super::document::PdfDocument;
use super::lexer::{Lexer, Token};
use super::object::{Dict, Object, PdfStream};
use crate::{FormatError, Result};

/// Parse exactly one object starting at `lex`'s current position.
///
/// Handles the `n g R` indirect-reference form via bounded look-ahead. Stream
/// bodies are read by `parse_stream_body`, which needs the document to resolve
/// an indirect `/Length`; when `doc` is `None` (e.g. parsing an object-stream's
/// flat token list, which never contains streams) the `stream` keyword is left
/// to fall through as a bare keyword.
pub(super) fn parse_object(lex: &mut Lexer, doc: Option<&PdfDocument>) -> Result<Object> {
    let tok = lex
        .next_token()?
        .ok_or_else(|| FormatError::Invalid("pdf: unexpected EOF parsing object".into()))?;
    object_from_token(tok, lex, doc)
}

pub(super) fn object_from_token(
    tok: Token,
    lex: &mut Lexer,
    doc: Option<&PdfDocument>,
) -> Result<Object> {
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
        if let Ok(Some(Token::Keyword(ref k))) = lex.next_token() {
            if k == b"R" && n >= 0 && (0..=u16::MAX as i64).contains(&g) {
                return Ok(Object::Ref(n as u32, g as u16));
            }
        }
    }
    // Not `n g R`: rewind and treat `n` as a plain integer.
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

/// Read the next token expecting an integer.
pub(super) fn expect_int(lex: &mut Lexer) -> Result<i64> {
    match lex.next_token()? {
        Some(Token::Int(n)) => Ok(n),
        other => Err(FormatError::Invalid(format!(
            "pdf: expected integer, got {:?}",
            other
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
