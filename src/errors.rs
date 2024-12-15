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
    details: String,
}

#[derive(Debug)]
enum ErrorKind {
    InvalidEntry,
    InvalidProof,
    InvalidSuccession,
    VerificationFailed,
    CryptoError,
    DatabaseError,
}

impl Error {
    pub fn invalid_entry(msg: impl Into<String>, details: impl Into<String>) -> Self {
        let details = details.into();
        Self {
            src: None,
            span: None,
            msg: msg.into(),
            kind: ErrorKind::InvalidEntry,
            details,
        }
    }

    pub fn invalid_proof(msg: impl Into<String>, details: impl Into<String>) -> Self {
        let details: String = details.into();
        Self {
            src: None,
            span: None,
            msg: msg.into(),
            kind: ErrorKind::InvalidProof,
            details,
        }
    }

    pub fn invalid_succession(msg: impl Into<String>, details: impl Into<String>) -> Self {
        let details = details.into();
        Self {
            src: None,
            span: None,
            msg: msg.into(),
            kind: ErrorKind::InvalidSuccession,
            details,
        }
    }

    pub fn verification_failed(msg: impl Into<String>, details: impl Into<String>) -> Self {
        let details = details.into();
        Self {
            src: None,
            span: None,
            msg: msg.into(),
            kind: ErrorKind::VerificationFailed,
            details,
        }
    }

    pub fn crypto_error(msg: impl Into<String>, details: impl Into<String>) -> Self {
        let details = details.into();
        Self {
            src: None,
            span: None,
            msg: msg.into(),
            kind: ErrorKind::CryptoError,
            details,
        }
    }

    pub fn database_error(msg: impl Into<String>, details: impl Into<String>) -> Self {
        let details = details.into();
        Self {
            src: None,
            span: None,
            msg: msg.into(),
            kind: ErrorKind::DatabaseError,
            details,
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
            ErrorKind::InvalidEntry => write!(f, "Access validation failed"),
            ErrorKind::InvalidProof => write!(f, "Proof verification failed"),
            ErrorKind::InvalidSuccession => write!(f, "Key succession validation failed"),
            ErrorKind::VerificationFailed => write!(f, "Verification operation failed"),
            ErrorKind::CryptoError => write!(f, "Cryptographic operation failed"),
            ErrorKind::DatabaseError => write!(f, "Database operation failed"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
