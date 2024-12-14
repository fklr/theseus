use miette::{Diagnostic, SourceSpan};
use std::fmt;

#[derive(Debug, Diagnostic)]
pub struct Error {
    #[source_code]
    src: Option<String>,
    #[label("Error occurred here")]
    span: Option<SourceSpan>,
    msg: String,
    kind: ErrorKind,
}

#[derive(Debug)]
enum ErrorKind {
    InvalidEntry,
    InvalidProof,
    InvalidSuccession,
    VerificationFailed,
    CryptoError,
}

impl Error {
    pub fn invalid_entry(msg: impl Into<String>) -> Self {
        Self {
            src: None,
            span: None,
            msg: msg.into(),
            kind: ErrorKind::InvalidEntry,
        }
    }

    pub fn invalid_proof(msg: impl Into<String>) -> Self {
        Self {
            src: None,
            span: None,
            msg: msg.into(),
            kind: ErrorKind::InvalidProof,
        }
    }

    pub fn invalid_succession(msg: impl Into<String>) -> Self {
        Self {
            src: None,
            span: None,
            msg: msg.into(),
            kind: ErrorKind::InvalidSuccession,
        }
    }

    pub fn verification_failed(msg: impl Into<String>) -> Self {
        Self {
            src: None,
            span: None,
            msg: msg.into(),
            kind: ErrorKind::VerificationFailed,
        }
    }

    pub fn crypto_error(msg: impl Into<String>) -> Self {
        Self {
            src: None,
            span: None,
            msg: msg.into(),
            kind: ErrorKind::CryptoError,
        }
    }

    pub fn with_source(mut self, source: String, span: impl Into<SourceSpan>) -> Self {
        self.src = Some(source);
        self.span = Some(span.into());
        self
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ErrorKind::InvalidEntry => write!(f, "Invalid entry: {}", self.msg),
            ErrorKind::InvalidProof => write!(f, "Invalid proof: {}", self.msg),
            ErrorKind::InvalidSuccession => write!(f, "Invalid succession: {}", self.msg),
            ErrorKind::VerificationFailed => write!(f, "Verification failed: {}", self.msg),
            ErrorKind::CryptoError => write!(f, "Cryptographic error: {}", self.msg),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
