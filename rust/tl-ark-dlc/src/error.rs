//! Typed errors. No function in this crate panics on untrusted input.

use std::fmt;

/// All failures surfaced by the crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Input is malformed (bad hex, wrong length, bad character, ...).
    Malformed(&'static str),
    /// Input exceeds a documented bound.
    TooLarge(&'static str),
    /// A uniqueness constraint was violated.
    Duplicate(&'static str),
    /// A referenced record does not exist.
    NotFound(&'static str),
    /// A store limit was reached.
    Capacity(&'static str),
    /// The store failed to persist (the caller must treat the operation as not done).
    Storage(&'static str),
    /// A signing nonce was already used (or reserved) for another message.
    NonceReused {
        /// Event id.
        event_id: String,
        /// Outcome index.
        index: u32,
    },
    /// The writer token is not the current single writer.
    StaleWriter,
    /// An attestation was requested before the event matured.
    NotMatured,
    /// The signature's R does not equal the announced nonce point for that outcome index.
    RBindingMismatch {
        /// Outcome index.
        index: u32,
    },
    /// A signature or announcement signature failed verification.
    SignatureInvalid,
    /// Underlying curve / hashing operation failed (negligible-probability or invalid key).
    Crypto(&'static str),
    /// Lifecycle transition not allowed.
    IllegalTransition {
        /// From state.
        from: &'static str,
        /// To state.
        to: &'static str,
    },
    /// Arithmetic overflow in a value computation.
    Overflow,
    /// A validation rule rejected the request.
    Rejected(&'static str),
    /// The chain adapter reported a failure.
    Chain(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Malformed(m) => write!(f, "malformed: {m}"),
            Error::TooLarge(m) => write!(f, "too large: {m}"),
            Error::Duplicate(m) => write!(f, "duplicate: {m}"),
            Error::NotFound(m) => write!(f, "not found: {m}"),
            Error::Capacity(m) => write!(f, "capacity: {m}"),
            Error::Storage(m) => write!(f, "storage: {m}"),
            Error::NonceReused { event_id, index } => {
                write!(f, "nonce reuse refused for event {event_id} index {index}")
            }
            Error::StaleWriter => write!(f, "stale writer token"),
            Error::NotMatured => write!(f, "event not matured"),
            Error::RBindingMismatch { index } => {
                write!(f, "signature R differs from announced R at index {index}")
            }
            Error::SignatureInvalid => write!(f, "signature invalid"),
            Error::Crypto(m) => write!(f, "crypto: {m}"),
            Error::IllegalTransition { from, to } => {
                write!(f, "illegal transition {from} -> {to}")
            }
            Error::Overflow => write!(f, "arithmetic overflow"),
            Error::Rejected(m) => write!(f, "rejected: {m}"),
            Error::Chain(m) => write!(f, "chain adapter: {m}"),
        }
    }
}

impl std::error::Error for Error {}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, Error>;
