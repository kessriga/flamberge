//! The PDF tokenizer: a byte-cursor over the whole document.
//!
//! [`Lexer`] produces [`Token`]s; assembling them into an [`Object`](super::object::Object)
//! graph is the parser's job ([`super::parser`]). The cursor exposes its
//! position ([`Lexer::pos`]) so the parser can seek (indirect objects live at
//! byte offsets named by the cross-reference table) and rewind (bounded
//! look-ahead for `n g R` references).

use crate::{FormatError, Result};

/// A single lexical token. Delimiters `<<`, `>>`, `[`, `]` are distinct
/// variants; all other bare word tokens (`obj`, `R`, `stream`, `n`, `f`, …)
/// become `Keyword`. `true`/`false`/`null` are folded into value tokens.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum Token {
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

/// Value of a single hex digit, or `None`.
pub(super) fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Cursor-based tokenizer over the whole PDF byte buffer.
pub(super) struct Lexer<'a> {
    /// The full document bytes (the parser reads stream bodies directly here).
    pub(super) data: &'a [u8],
    /// The current byte offset (the parser saves/restores this to seek/rewind).
    pub(super) pos: usize,
}

impl<'a> Lexer<'a> {
    pub(super) fn new(data: &'a [u8]) -> Self {
        Lexer { data, pos: 0 }
    }

    pub(super) fn at(data: &'a [u8], pos: usize) -> Self {
        Lexer { data, pos }
    }

    pub(super) fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    /// Skip whitespace and `%`-comments (to end of line).
    pub(super) fn skip_ws(&mut self) {
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
    pub(super) fn next_token(&mut self) -> Result<Option<Token>> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
