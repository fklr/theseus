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
    ValidationFailed,
    VerificationFailed,
    CryptoError,
    CircuitError,
    CommitmentError,
    MerkleError,
    SignatureError,
    DatabaseError,
    RateLimited,
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

    pub fn validation_failed(msg: impl Into<String>, details: impl Into<String>) -> Self {
        let details = details.into();
        Self {
            src: None,
            span: None,
            msg: msg.into(),
            kind: ErrorKind::ValidationFailed,
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

    pub fn circuit_error(msg: impl Into<String>, details: impl Into<String>) -> Self {
        let details = details.into();
        Self {
            src: None,
            span: None,
            msg: msg.into(),
            kind: ErrorKind::CircuitError,
            details,
        }
    }

    pub fn commitment_error(msg: impl Into<String>, details: impl Into<String>) -> Self {
        Self {
            src: None,
            span: None,
            msg: msg.into(),
            kind: ErrorKind::CommitmentError,
            details: details.into(),
        }
    }

    pub fn merkle_error(msg: impl Into<String>, details: impl Into<String>) -> Self {
        Self {
            src: None,
            span: None,
            msg: msg.into(),
            kind: ErrorKind::MerkleError,
            details: details.into(),
        }
    }

    pub fn signature_error(msg: impl Into<String>, details: impl Into<String>) -> Self {
        Self {
            src: None,
            span: None,
            msg: msg.into(),
            kind: ErrorKind::SignatureError,
            details: details.into(),
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

    pub fn rate_limited(msg: impl Into<String>, details: impl Into<String>) -> Self {
        let details = details.into();
        Self {
            src: None,
            span: None,
            msg: msg.into(),
            kind: ErrorKind::RateLimited,
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
            ErrorKind::ValidationFailed => write!(f, "Batch validation operation failed"),
            ErrorKind::VerificationFailed => write!(f, "Verification operation failed"),
            ErrorKind::CryptoError => write!(f, "Cryptographic operation failed"),
            ErrorKind::CircuitError => write!(f, "Circuit operation failed"),
            ErrorKind::CommitmentError => write!(f, "Commitment operation failed"),
            ErrorKind::MerkleError => write!(f, "Merkle tree operation failed"),
            ErrorKind::SignatureError => write!(f, "Signature operation failed"),
            ErrorKind::DatabaseError => write!(f, "Database operation failed"),
            ErrorKind::RateLimited => write!(f, "Rate limit exceeded"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
