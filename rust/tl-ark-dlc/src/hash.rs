//! SHA-256 based tagged hashing (BIP-340 construction) and an unambiguous, length-prefixed encoder.
//!
//! All hashing is delegated to `bitcoin::hashes`; nothing here implements a primitive.

use crate::error::{Error, Result};
use bitcoin::hashes::{sha256, Hash};

/// Plain SHA-256.
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(data).to_byte_array()
}

/// `SHA256(SHA256(tag) || SHA256(tag) || data)` (BIP-340 tagged hash; legacy `createTaggedHash`).
pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let t = sha256_bytes(tag.as_bytes());
    let mut buf = Vec::with_capacity(64 + data.len());
    buf.extend_from_slice(&t);
    buf.extend_from_slice(&t);
    buf.extend_from_slice(data);
    sha256_bytes(&buf)
}

/// Maximum length of one length-prefixed field.
pub const MAX_FIELD_LEN: usize = 64 * 1024;

/// Injective message builder: fixed-width integers and `u32`-length-prefixed byte strings.
#[derive(Default, Debug, Clone)]
pub struct Enc(Vec<u8>);

impl Enc {
    /// Empty encoder.
    pub fn new() -> Self {
        Enc(Vec::new())
    }

    /// Append a length-prefixed (u32 BE) byte string.
    pub fn lp(&mut self, bytes: &[u8]) -> Result<&mut Self> {
        if bytes.len() > MAX_FIELD_LEN {
            return Err(Error::TooLarge("encoded field"));
        }
        self.0.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        self.0.extend_from_slice(bytes);
        Ok(self)
    }

    /// Append a fixed 32-byte field.
    pub fn fixed32(&mut self, b: &[u8; 32]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }

    /// Append a u32 (big-endian).
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Append a u64 (big-endian).
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Append one byte.
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }

    /// Finish.
    pub fn finish(self) -> Vec<u8> {
        self.0
    }
}
