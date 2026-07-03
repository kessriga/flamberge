use thiserror::Error;

#[derive(Debug, Error)]
pub enum FormatError {
    #[error("unexpected end of data at offset {0}")]
    Truncated(usize),

    #[error("bad magic: {0}")]
    BadMagic(String),

    #[error("invalid structure: {0}")]
    Invalid(String),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("not yet implemented: {0}")]
    Unimplemented(&'static str),
}
